# commiter : adollking
# 22-08-2024

import logging
from logging.handlers import RotatingFileHandler 
import socket
import paramiko
import threading


#variables

# HOST_KEY=paramiko.RSAKey.generate(filename='host.key')
HOST_KEY = paramiko.RSAKey.generate(1024)
USER='root'
PASSWORD='1234'


#format logging 
logging_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

#log 
funner_logger = logging.getLogger('funnerLogger')
funner_logger.setLevel(logging.INFO)
funner_handler = RotatingFileHandler('audit.log', maxBytes=2000, backupCount=5)
funner_handler.setFormatter(logging_format)
funner_logger.addHandler(funner_handler)



cmd_logger = logging.getLogger('cmdLogger')
cmd_logger.setLevel(logging.INFO)
cmd_handler = RotatingFileHandler('cmd_audit.log', maxBytes=2000, backupCount=5)
cmd_handler.setFormatter(logging_format)
cmd_logger.addHandler(cmd_handler)


# Emulate a honeypot

def emulate_shell(channel, client_ip):
    channel.send(b'ssh@honeypot-local:~$ ')
    command = b""
    response = b""  # Initialize the 'response' variable
    while True:
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()
        
        command += char

        if char == b'\r':
            if command.strip() == b'exit':
                response = b'\n Goodbye!\r\n'
                channel.close()
            elif command.strip() == b'whoami':
                response = b'\n' + b'root\r\n'
            elif command.strip() == b'ls':
                response = b'\n' + b'pswrd.txt pswrd-backup.txt file3.txt ' + b'\r\n'
            elif command.strip() == b'cat pswrd.txt':
                response = b'\n' + b'admin:password\r\n'
            elif command.strip() == b'cat pswrd-backup.txt':
                response = b'\n' +'admin:password\r\n'
            elif command.strip() == b'cat file3.txt':
                response = b'\n' + b'file3 content\r\n'
            elif command.strip() == b'pwd':
                response = b'\n' + b'/root\r\n'
            elif command.strip() == b'help':
                response = b'\n' + b'Available commands: whoami, ls, cat, pwd, exit '+ b'\r\n'
            else: 
                response = b"\n" +bytes(command.strip()) + b"\r\n"


            channel.send(response)
            channel.send(b'ssh@honeypot-local:~$ ')
            cmd_logger.info(f'{client_ip} - {command.strip()}')
            command = b""
## ssh server 

class Server(paramiko.ServerInterface):

    def __init__(self,client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        funner_logger.info(f'Login from {self.client_ip} attempt: '+f'username: {username} - ' + f'pass: {password} ')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password ==  self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL
        

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(self, channel: paramiko.Channel, term: bytes, width: int, height: int, pixelwidth: int, pixelheight: int, modes: bytes) -> bool:
        return True
    
    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        command = str(command, 'utf-8')
        return True 

def client_handle(client,addr,username,password):
    client_ip = addr[0]
    print(f'Connection from {client_ip} has been established')
    funner_logger.info(f'Connection from {client_ip} has been established')
    try:
        transport = paramiko.Transport(client)
        transport.local_version = 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8'
        transport.add_server_key(HOST_KEY)
        server = Server(addr,username,password)
        transport.start_server(server=server)
        channel = transport.accept(100)
        if channel is None:
            return 

        standard_banner = "Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-151-generic x86_64)\r\n"
        channel.send(standard_banner) 
        emulate_shell(channel, client_ip=client_ip)
    except Exception as e:
        funner_logger.error(f'Error: {e}')
        client.close()
        print(f'Connection has been closed from {client_ip}')


#  provision the server

def honeypot_server(address, port,username,password):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(100) # port 100 
    print(f'Listening for connections on {address}:{port}')        

    while True:
        try:
            client,addr = sock.accept()
            ssh_honey_pot_thread = threading.Thread(target=client_handle,args=(client,addr,username,password))
            ssh_honey_pot_thread.start()
        except Exception as error:
            print(error)


honeypot_server('127.0.0.1',2021,'username','password')


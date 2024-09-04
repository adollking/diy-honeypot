# commiter : adollking
# 22-08-2024

import geoip2.webservice
import logging
from logging.handlers import RotatingFileHandler 
import socket
import paramiko
import threading
import datetime 
import re
import hashlib
import random
import threading
from twisted.internet import reactor


#variables
#Generate an RSA key and save it to a file
# HOST_KEY = paramiko.RSAKey.generate(2048)
# HOST_KEY.write_private_key_file('host.key')
HOST_KEY = paramiko.RSAKey(filename='host.key')
USER='root'
PASSWORD='1234'

#format logging 
logging_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

#log 
funner_logger = logging.getLogger('funnerLogger')
funner_logger.setLevel(logging.INFO)
funner_handler = RotatingFileHandler('audit.log', maxBytes=20000, backupCount=5)
funner_handler.setFormatter(logging_format)
funner_logger.addHandler(funner_handler)

cmd_logger = logging.getLogger('cmdLogger')
cmd_logger.setLevel(logging.INFO)
cmd_handler = RotatingFileHandler('cmd_audit.log', maxBytes=20000, backupCount=5)
cmd_handler.setFormatter(logging_format)
cmd_logger.addHandler(cmd_handler)

# TODO : error show previeus command when ping is running
# TODO : fix ctc+c when ping is running 

KEY_UP = b'\x1b[A'
KEY_DOWN = b'\x1b[B'
KEY_RIGHT = b'\x1b[C'
KEY_LEFT = b'\x1b[D'

class command_ping:
    def __init__(self, args, channel, client_ip):
        self.args = args
        self.channel = channel
        self.client_ip = client_ip
        self.start()

    def start(self):
        self.host = None
        for arg in self.args:
            if not arg.startswith(b'-'):
                self.host = arg.strip()
                break

        if not self.host:
            usage_lines = [
                b'Usage: ping [-LRUbdfnqrvVaA] [-c count] [-i interval] [-w deadline]',
                b'            [-p pattern] [-s packetsize] [-t ttl] [-I interface or address]',
                b'            [-M mtu discovery hint] [-S sndbuf]',
                b'            [ -T timestamp option ] [ -Q tos ] [hop1 ...] destination'
            ]
            for line in usage_lines:
                self.channel.send(line + b'\r\n')
            return

        if re.match(b'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', self.host):
            self.ip = self.host
        else:
            s = hashlib.md5(self.host).hexdigest()
            self.ip = b'.'.join([str(int(x, 16)).encode() for x in (s[0:2], s[2:4], s[4:6], s[6:8])])

        self.channel.send(b'PING ' + self.host + b' (' + self.ip + b') 56(84) bytes of data.\r\n')
        self.count = 0
        self.showreply()

    def showreply(self):
        ms = 40 + random.random() * 10
        self.channel.send(
            b'64 bytes from ' + self.host + b' (' + self.ip + b'): icmp_seq=' + str(self.count + 1).encode() +
            b' ttl=50 time=' + f'{ms:.1f}'.encode() + b' ms\r\n'
        )
        self.count += 1
        self.scheduled = threading.Timer(1, self.showreply)
        self.scheduled.start()

    def ctrl_c(self):
        self.scheduled.cancel()
        self.channel.send(b'--- ' + self.host + b' ping statistics ---\r\n')
        self.channel.send(
            f'{self.count} packets transmitted, {self.count} received, 0% packet loss, time 907ms\r\n'.encode('utf-8')
        )
        self.channel.send(b'rtt min/avg/max/mdev = 48.264/50.352/52.441/2.100 ms\r\n'.encode('utf-8'))

def emulate_shell(channel, client_ip, address, username):
    prompt = f'{username}@{address[0]}:~$ '.encode('utf-8')
    channel.send(prompt)
    command = b""
    history = []  
    history_index = -1
    active_command = None
    
    while True:
        char = channel.recv(1)
        cursor_position = 0
        
        # backspace
        if char in {b'\x08', b'\x7f'}:
            if len(command) > 0:
                command = command[:-1]
                channel.send(b'\x08 \x08')
            continue

        # Ctrl+C
        if char == b'\x03': 
            if active_command:
                active_command.ctrl_c()
                active_command = None
            channel.send(b'^C\r\n')
            # Clear command buffer
            command = bytearray()  
            channel.send(prompt)
        
        # arrow keys
        if char == b'\x1b':  
            char += channel.recv(2) 
            
            if char == KEY_UP:
                if history:
                    history_index = (history_index - 1) % len(history)
                    command = history[history_index]
                    channel.send(b'\r\x1b[K' + prompt + command)
            elif char == KEY_DOWN:
                if history:
                    history_index = (history_index + 1) % len(history)
                    if history_index < len(history):
                        command = history[history_index]
                    else:
                        command = b""
                    # Clear the current line and print the command from history
                    channel.send(b'\r\x1b[K' + prompt + command)
            elif char == KEY_RIGHT:
                if cursor_position < len(command):
                    cursor_position += 1
                    channel.send(KEY_RIGHT)  
            elif char == KEY_LEFT:
                if cursor_position > 0:
                    cursor_position -= 1
                    channel.send(KEY_LEFT) 

            continue
        channel.send(char)
        
        if not char:
            channel.close()
            break
        
        command += char

        if char == b'\r':
            # Add the command to history
            
            if command.strip():
                history.append(command.strip())
                history_index = len(history)

            if command.strip() == b'exit':
                channel.send(response)
                channel.close()
                break
            elif command.strip().startswith(b'ping'):
                args = command.strip().split()
                funner_logger.info(f'{client_ip} - {args} ')
                command_ping(args, channel, client_ip)
            else: 
                response = handle_command(command.strip(), channel, client_ip)

            command = bytearray()  
            if response:
                channel.send(response)

                
            channel.send(prompt)
            cmd_logger.info(f'{client_ip} - {command.strip().decode()}')
            command = b""


# handle command 
def handle_command(command, channel, client_ip):
    if command == b'exit':
        channel.close()
    elif command == b'whoami':
        response = b'\nroot\r\n'
    elif command == b'ls':
        response = b'\npswrd.txt pswrd-backup.txt file3.txt\r\n'
    elif command == b'cat pswrd.txt':
        response = b'\nadmin:password\r\n'
    elif command == b'cat pswrd-backup.txt':
        response = b'\nadmin:password\r\n'
    elif command == b'cat file3.txt':
        response = b'\nfile3 content\r\n'
    elif command == b'pwd':
        response = b'\n/root\r\n'
    elif command == b'help':
        response = b'\nAvailable commands: ping, whoami, ls, cat, pwd, history, exit\r\n'
    else:
        response = b'\n' + command + b': command not found\r\n'
    return response
    


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
        funner_logger.info(f'Country: {self.getCountryIp(self.client_ip)}')
        
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
    def getCountryIp(self,ip):
        try:
            reader = geoip2.webservice.Client(123456, '123456')
            response = reader.city(ip)
            return response.country.name
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception as e:
            funner_logger.error(f'Unknown exception: {e}')
            return "Unknown"

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
        
        now = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")

        standard_banner = "Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-151-generic x86_64)\r\n"

        channel.send(standard_banner) 
        emulate_shell(channel, client_ip=client_ip,address=addr,username=username)
    except Exception as e:
        funner_logger.error(f'Error: {e}')
        client.close()
        print(f'Connection has been closed from {client_ip}')


#  provision the server

def honeypot_server(address, port,username,password):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(100) 
    print(f'Listening for connections on {address}:{port}')        

    while True:
        try:
            client,addr = sock.accept()
            ssh_honey_pot_thread = threading.Thread(target=client_handle,args=(client,addr,username,password))
            ssh_honey_pot_thread.start()
        except Exception as error:
            print(error)




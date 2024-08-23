import argparse
from ssh_honey_pot import *

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="SSH Honey Pot")
    
    parser.add_argument("-a", "--address", type=str, help="Address to listen on", required=True)
    parser.add_argument("-p", "--port",  type=int, help="Port to listen on" , required=True)
    parser.add_argument("-u ", "--username", type=str, default="root", help="Username to listen on", required=False)
    parser.add_argument("-pw", "--password", type=str, default="toor", help="Password to listen on", required=False) 
    args = parser.parse_args()


    try:
        if args.address and args.port and args.username and args.password:
            print("SSH Honey Pot started on port: ", args.port)
            honeypot_server(args.address, args.port, args.username, args.password)
        
    except :
        pass

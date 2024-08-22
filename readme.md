# DIY honey pot

## desciption

   this project using  python 3.11.8

   ```bash
      pip install -r requirements.txt
   ```

   change 
   ```
   honeypot_server('127.0.0.1',2021,'username','password')
   ``` 
   with your server ip and custom port , custom username and passowrd 

   you can use custom key in 
   ```
   # HOST_KEY=paramiko.RSAKey.generate(filename='host.key')
   HOST_KEY = paramiko.RSAKey.generate(1024) 
   ```

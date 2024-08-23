# DIY honey pot

## desciption

   this project using  python 3.11.8

   ```bash
      pip install -r requirements.txt
   ```

   run command with your server ip and custom port , custom username and password 

   ```bash 
      python3 honey_pot.py -a 127.0.0.1 -p 2024 -u root -pw root
   ``` 
   you can use custom key in 
   ```
   # HOST_KEY=paramiko.RSAKey.generate(filename='host.key')
   HOST_KEY = paramiko.RSAKey.generate(1024) 
   ```

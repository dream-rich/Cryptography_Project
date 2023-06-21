import socket
import struct
import sqlite3, random, threading
import time
import binascii
import ssl
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json, requests

# Database=========================================
url = "https://ap-southeast-1.aws.data.mongodb-api.com/app/data-wwzqj/endpoint/data/v1/action/"
apikey = open("api.key",'r').read()
headers = {
  'Content-Type': 'application/json',
  'Access-Control-Request-Headers': '*',
  'api-key': apikey,
} 
# =========================================

# Create an SSL context with TLS 1.3 support
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile="new.crt")

# Khởi tạo socket server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('0.0.0.0', 1234))
server_socket.listen(10)


# Global variables
clients = []
session = []
public_key = []
session_otp = []
otp = ''
logtime = []

print("Waiting for client connection...")

# Chấp nhận kết nối từ client

def send(message : str,client : socket.socket):
   client.send(message.encode())


def Decor():

    content = """
    +------------------------------------------------------------------+
    |  One Time Password (OTP) Based on Advanced Encrypted Standard    |
    |            (AES) and Linear Congruential Generator(LCG)          |
    +------------------------------------------------------------------+
    """

    print(content)

def LCG(cipher,LOGTIME): 
    otp = ''
    m = 2**31
    a = 1103515245  
    c = 12345  
    seed = [0]*6
    m0 = int(LOGTIME) % len(cipher)
    seed[0] = (a * m0 + c) % m 
    seed[1] = (a * seed[0] + c) % m
    seed[2] = (a * seed[1] + c) % m
    seed[3] = (a * seed[2] + c) % m
    seed[4] = (a * seed[3] + c) % m
    seed[5] = (a * seed[4] + c) % m
    for i in seed:
        otp_char =  str(cipher[i % len(cipher)])
        if(otp_char.isdigit()):
            otp += otp_char
        else:
            otp += str(int(ord(otp_char) % 10))
    return otp

def ECDH(client_socket):
    global secret_key

    # Khởi tạo khóa riêng và khóa công khai của server
    secret_key = server_private_key = ec.generate_private_key(ec.SECP256R1())
    server_public_key = server_private_key.public_key()
    server_public_key_der = server_public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return server_public_key_der

def GetDictValue(dict,client):
    for i in dict:
        for key in i.keys():
            if key == client:
                return str(i[key])

def generate_OTP(client : socket.socket, logtime):
    global otp
    
    try:
        otp = OTPGen(client, logtime)
        print(f"OTP: {otp}")
                
    except Exception as e:
        print(e)
        
def OTPGen(client : socket.socket, LOGTIME):
    global secret_key
    global otp
    username = GetDictValue(session,client)
 
    client_public_key_bytes = bytes.fromhex(str(GetDictValue(public_key,client))) 
    client_public_key = serialization.load_der_public_key(
        client_public_key_bytes,
        backend=default_backend()
    )
    shared_key = secret_key.exchange(ec.ECDH(), client_public_key)
    shared_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
    ).derive(shared_key)
    print(f"Shared key: {shared_key}")

    # cipher = Cipher(algorithms.AES(shared_key), modes.CFB(initialization_vector=shared_key[:16]), backend=default_backend())
    cipher = Cipher(algorithms.AES(shared_key), modes.GCM(shared_key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()

    print(f"LOGTIME: {LOGTIME}")
    print(f"Username: {username}")
    plaintext = str(username) + str(LOGTIME)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    otp = LCG(cipher=binascii.hexlify(ciphertext).decode(),LOGTIME=LOGTIME)

    session_otp.append({client:otp})
    
    return otp


def uploadUser(username,email,password):
    action = url + "insertOne"
    payload = json.dumps({
    "collection": "Users",
    "database": "Data",
    "dataSource": "MMH",
    "document": {
        "name": username,
        "email": email,
        "password": password
    }
    })
    requests.request("POST", action, headers=headers, data=payload)


def CheckUsername(username):
    action = url + "find"
    payload = {
        "collection": "Users",
        "database": "Data",
        "dataSource": "MMH",
        "filter": {"name": username},
        "projection": {"name": 1}
    }
    response = requests.post(action, headers=headers, json=payload)
    usernames = response.json().get('documents', [])
    return any(name['name'] == username for name in usernames)



def signup(username, password, email):
    if(CheckUsername(username) == True):
        return False
    else:
        uploadUser(username=username,email=email,password=password)
        return True

def signin(username,password):
    action = url + "findOne"
    payload = json.dumps({
    "collection": "Users",
    "database": "Data",
    "dataSource": "MMH",
    "projection": {
        "name": username,
        "password": password
    }
    })
    response = requests.request("POST", action, headers=headers, data=payload)  
    response = json.loads(response.text)['document']
    print(response)
    if(response):
        return True 
    else:
        return False
    
def auth(rcv, client):  
    otp_rcv = rcv.split(' ')[1]
    if(rcv.startswith("@auth")):
        if(otp_rcv == otp):
            timeout = float(time.time() / 60) - int(GetDictValue(logtime, client))
            print(f"Timeout: {timeout} seconds")
            if(timeout) <= 30:
                print("[+] " + GetDictValue(session,client) + " verified!")
                send("Authenticated",client)
                logtime.pop()
                public_key.pop()
                session.pop()
            else: 
                send("OTP expired",client)                
        else:
            send("Wrong OTP",client)
            
    return


def handle(message : str, client : socket.socket):
    if(message.startswith("@signup")):
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        email = msg[3]
        
        signup_thread = threading.Thread(target=signup,args=[username,password,email])
        signup_thread.start()

        state = signup(username, password,email)
        if state == True:
            print("[+] " + username + " signed up!")
            send("You have signed up, let's sign in.",client)
        elif state == False:
            send("Username already existed!",client)
        else: 
            print("Error")
        
    if(message.startswith("@signin")):
        try:
            username = ""
            msg = message.split(' ')
            username = msg[1]
            password = msg[2]
            logged = signin(username,password)
            
            if(logged):                       
                # ECDH
                key = ECDH(client)
                client_pk = message.split(' ')[3]
                send("@pk " + binascii.hexlify(key).decode(),client)
                public_key.append({client:client_pk})
                
                # Notify client
                session.append({client:username})
                print("[+] " + username + " signed in!")
                
                # OTP verification
                logtime.append({client:int(time.time() / 60)})
                otp_thread = threading.Thread(target=generate_OTP,args=(client, GetDictValue(logtime,client)))
                otp_thread.start()      
                
                rcv = client.recv(1024).decode()
                auth(rcv, client)
                
            else:
                send("Wrong password",client)     
                return   
     
            return
        except Exception as e:
            print(e)
            
    if(message.startswith("@resend")):
        try: 
            logtime.pop()
            send("Client requested new OTP",client)
            logtime.append({client:int(time.time() / 60)})
            threading.Thread(target=generate_OTP,args=(client, GetDictValue(logtime, client))).start()
            
            rcv_2 = client.recv(1024).decode()
            auth(rcv_2, client)
        except Exception as e:
            print(e)        

def handle_client(client: ssl.SSLSocket):
    while True:
        try:
            data = client.recv(4096).decode().strip()
            if not data:
                break
            msg = handle(message=data, client=client)
            if msg:
                print(f"[POST]: {msg}")
        except Exception as e:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            break   

def main():
    while True:
        with context.wrap_socket(server_socket, server_side=True) as ssock:
            try:
                client, addr = ssock.accept()
                client_thread = threading.Thread(target=handle_client, args=(client,))
                client_thread.start()
                clients.append(client)
            except Exception as e:
                print(e)
        
if __name__=="__main__":
    global secret_key
    Decor()
    main()

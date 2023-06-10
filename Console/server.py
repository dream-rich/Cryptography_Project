import socket
import struct
import sqlite3, random, threading
import time
import binascii
import ssl
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# Khởi tạo socket server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 999))
server_socket.listen(10)

# Global variables
clients = []
session = []
public_key = []
session_otp = []
otp = ''
logtime = []
stop_thread = False

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

def generate_new_OTP(client : socket.socket, logtime):
    global stop_thread
    global otp
    
    try:
        otp = OTPGen(client, logtime)
        print(f"OTP 1: {otp}")
        
        while stop_thread != True:
            time.sleep(30)           
            timestamp = int(time.time())
            otp = OTPGen(client, timestamp)
            print(f"New OTP: {otp}")
                
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

    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(initialization_vector=shared_key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()

    plaintext = str(username) + str(LOGTIME)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    otp = LCG(cipher=binascii.hexlify(ciphertext).decode(),LOGTIME=LOGTIME)

    session_otp.append({client:otp})
    
    return otp

def signup(username, password, email):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    query = "INSERT INTO USERS VALUES (?, ?, ?)"
    values = (username, password, email)

    cursor.execute(query, values)

    conn.commit()
    conn.close()
    return

def signin(username,password):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute(
        f"SELECT PASSWORD FROM USERS WHERE USERNAME = '{username}'"
    )
    sv_password = c.fetchall()[0][0]
    conn.commit()
    conn.close()
    if(sv_password == password):
        return True
    else:
        return False
  
def handle(message : str, client : socket.socket):
    global stop_thread
    
    if(message.startswith("@signup")):
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        email = msg[3]
        
        signup_thread = threading.Thread(target=signup,args=[username,password,email])
        signup_thread.start()
        print("[+] " + username + " signed up!")
        send("You have signed up, let's sign in.",client)
        return
        
    if(message.startswith("@signin")):
        timestamp = int(time.time())
        print(timestamp)
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
            otp_thread = threading.Thread(target=generate_new_OTP,args=(client, timestamp))
            otp_thread.start()      
            
            rcv = client.recv(1024).decode()
            otp_rcv = rcv.split(' ')[1]
            stop_thread = True
            
        else:
           send("Wrong password",client)     
           return   
           
        if(otp_rcv == otp):
            print("[+] " + username + " verified!")
            send("Authenticated",client)
            stop_thread = True
        else:
            send("Wrong OTP",client)
            
        return

def handle_client(client):
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
        client, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client,))
        client_thread.start()
        clients.append(client)
        
if __name__=="__main__":
    global secret_key
    Decor()
    main()


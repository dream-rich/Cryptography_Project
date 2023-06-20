import socket
import struct
import sqlite3, random, threading
import time
import binascii
import ssl
import json
import pymongo
from pymongo import MongoClient
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json, requests
# Database=========================================
client = pymongo.MongoClient('https://ap-southeast-1.aws.data.mongodb-api.com/app/data-wwzqj/endpoint/data/v1/action/')
with open("api.key", 'r') as file:
    apikey = file.read().strip()
headers = {
        'Content-Type': 'application/json',
        'Access-Control-Request-Headers': '*',
        'api-key': apikey,
        }
# =========================================

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# Khởi tạo socket server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("0.0.0.0", 1234))
server_socket.listen(10)

# Global variables
clients = []
session = []
public_key = []
session_otp = []
otp = ''
logtime = []
stop_thread = False

# Specify the database and collection names
db = client['Data']
collection = db['Users']

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

    # cipher = Cipher(algorithms.AES(shared_key), modes.CFB(initialization_vector=shared_key[:16]), backend=default_backend())
    cipher = Cipher(algorithms.AES(shared_key), modes.GCM(shared_key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()

    plaintext = str(username) + str(LOGTIME)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    otp = LCG(cipher=binascii.hexlify(ciphertext).decode(),LOGTIME=LOGTIME)

    session_otp.append({client:otp})

    return otp

def uploadUser(username, email, password):
    document = {
        "name": username,
        "email": email,
        "password": password
    }
    collection.insert_one(document)

def CheckUsername(username):
    query = {"name": username}
    result = collection.find(query, {"name": 1})
    return result.count() > 0

def signup(username, password, email):
    if CheckUsername(username):
        return False
    else:
        uploadUser(username, email, password)
        return True

def signin(username, password):
    query = {"name": username, "password": password}
    result = collection.find_one(query)
    if result:
        return True
    else:
        return False

def auth(rcv, client):
    otp_rcv = rcv.split(' ')[1]
    if(rcv.startswith("@auth")):
        if(otp_rcv == otp):
            timeout = float(time.time()) - int(GetDictValue(logtime, client))
            print(f"Timeout: {timeout} seconds")
            if(timeout) <= 30:
                print("[+] " + GetDictValue(session,client) + " verified!")
                send("Authenticated",client)
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
            logtime.append({client:int(time.time())})

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
            logtime.append({client:int(time.time())})
            threading.Thread(target=generate_OTP,args=(client, GetDictValue(logtime, client))).start()

            rcv_2 = client.recv(1024).decode()
            auth(rcv_2, client)
        except Exception as e:
            print(e)

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

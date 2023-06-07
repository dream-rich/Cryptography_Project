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
server_socket.bind(('127.0.0.1', 1234))
server_socket.listen(10)
clients = []
session = []
public_key = []
session_otp = []
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

    # print("Shared secret key:", shared_key.hex())

def GetDictValue(dict,client):
    for i in dict:
        for key in i.keys():
            if key == client:
                return i[key]


def OTPGen(client : socket.socket):
    global secret_key
    LOGTIME = GetDictValue(logtime,client)
    username = GetDictValue(session,client)
 
    client_public_key_bytes = bytes.fromhex(GetDictValue(public_key,client)) 
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
    # print(binascii.hexlify(shared_key))
    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(initialization_vector=shared_key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()
    # plaintext = username + email + str(LOGTIME)
    plaintext = username + str(LOGTIME)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    # print(ciphertext)
    otp = LCG(cipher=binascii.hexlify(ciphertext).decode(),LOGTIME=LOGTIME)
    # print(otp)
    session_otp.append({client:otp})
    return


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
    if(message.startswith("@signup")):
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        email = msg[3]
        send("You have signed up, let's sign in.",client)
        signup_thread = threading.Thread(target=signup,args=[username,password,email])
        signup_thread.start()
        return "[+] " + username + " signed up!"
    if(message.startswith("@signin")):
        timestamp = int(time.time()/60)
        logtime.append({client:timestamp})
        # print(timestamp)
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        logged = signin(username,password)
        if(logged):
            session.append({client:username})
            send("Please enter OTP to authorize",client)
            return None
        else:
           send("Wrong password",client)
           return None
    if(message.startswith('@otp')):
        otp_thread = threading.Thread(target=OTPGen,args=[client])
        otp_thread.start()
        return None
    if(message.startswith('@ecdh')):
        key = ECDH(client)
        # print(key)
        client_pk = message.split(' ')[1]
        send("@pk " + binascii.hexlify(key).decode(),client)
        public_key.append({client:client_pk})
        return None
    if(message.startswith('@auth')):
        otp = message.split(' ')[1]
        svotp = GetDictValue(session_otp,client)
        timeout = (time.time() - GetDictValue(logtime,client)) % 60
        print(timeout)
        if(otp == str(svotp)):
            if(timeout <= 30):
                send("Authenticated",client)
            else:
                send("OTP Timeouted",client)
        else:
            send("Wrong OTP",client)
    else:
        return message

def handle_client(client):
    while True:
        try:
            data = client.recv(4096)
            if not data:
                break
            message = data.decode()
            msg = handle(message=message, client=client)
            if msg:
                print(f"[POST]: {msg}")
        except Exception as e:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            break

def LISTEN():
    while True:
        client, addr = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client,))
        client_thread.start()
        clients.append(client)

def main():
    LISTEN()
if __name__=="__main__":
    global secret_key
    Decor()
    main()


import socket
import struct
import sqlite3, random
import hashlib , binascii, threading
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Khởi tạo socket client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 1234))
print("Connected to server!")

def Decor():
    message = """
    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    One Time Password (OTP) Based on Advanced Encrypted Standard (AES) 
                and Linear Congruential Generator(LCG)
    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    """
    print(message)

def Menu():
    message = """
    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< 

    /register <username> <password> <email>  : register
    /login <username> <password>             : login

    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    """
    print(message)
def LCG(cipher):
    global LOGTIME
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
    



def OTPGen(username):
    global secret_key    
    global LOGTIME
    global server_public_key

    server_public_key_bytes = bytes.fromhex(server_public_key)
    server_public_key = serialization.load_der_public_key(
        server_public_key_bytes,
        backend=default_backend()
    )
    shared_key = secret_key.exchange(ec.ECDH(), server_public_key)
    shared_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
    ).derive(shared_key)
    # print(binascii.hexlify(shared_key))

    cipher = Cipher(algorithms.AES(shared_key), modes.CFB(initialization_vector=shared_key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()

    plaintext = username + str(LOGTIME)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    # print(ciphertext)
    otp = LCG(cipher=binascii.hexlify(ciphertext).decode())
    return otp

def handle_input(message : str):
    global NAME
    global LOGTIME
    if(message):
        if message.startswith('/menu'):
            Menu() 
            return None
        if message.startswith('/register') or message.startswith('/login'):
            msg = message.split(' ')
            prefix = msg[0]
            username = msg[1]
            password = msg[2]
            salt = password[2:6]
            NAME = username
            hashed = binascii.hexlify(hashlib.sha256((password + salt).encode()).digest())
            if(prefix == '/register'):
                email = msg[3]
                to_send = f"@register {username} {hashed.decode()} {email}"
            else:
                timestamp = int(time.time()/60)
                LOGTIME = str(timestamp)
                # print(timestamp)
                to_send = f"@login {username} {hashed.decode()}"
            # print(to_send)
            return to_send.encode()
        if message.startswith('/ecdh'):
            key = ECDH()
            to_send = f'@ecdh {binascii.hexlify(key).decode()}'
            return to_send.encode()
        if(message.startswith('/otp')):
            to_send = message.replace('/otp','@otp')
            print("Here is your OTP : ",OTPGen(NAME))
            return to_send.encode()
        if(message.startswith('/auth')):
            return message.replace('/auth','@auth').encode()
        return message.encode()
    else:
        return None

def client_receive():
    global isAuth
    global server_public_key
    while True:
        try:
            message = client_socket.recv(2048).decode('utf-8')
            if(message):
                if(message.startswith('Logged in!')):
                    isAuth = True
                    print(f"[NOTI] : {message}")
                elif(message.startswith('@pk')):
                    server_public_key = message.split(' ')[1]
                    # print(server_public_key)
                else:
                    print(f"[NOTI] : {message}")
            else:
                pass
        except:
            print('Error!')
            client_socket.close()
            break

def client_send():
    while True:
        message = handle_input(input(">> "))
        if(message):
            client_socket.send(message)
            # print(message)


def ECDH():
    global secret_key
    # # Nhận tên curve từ server
    # curve_name = client_socket.recv(8).decode('ascii')
    # print("Curve name received")

    # Khởi tạo khóa riêng và khóa công khai của client
    client_private_key = ec.generate_private_key(ec.SECP256R1())
    secret_key = client_private_key
    client_public_key = client_private_key.public_key()
    public_key_der = client_public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # print(binascii.hexlify(public_key_der))
    return public_key_der    

def main():
    receive_thread = threading.Thread(target=client_receive)
    receive_thread.start()
    send_thread = threading.Thread(target=client_send)
    send_thread.start()


if __name__=="__main__":
    global secret_key
    global server_public_key
    global NAME 
    global LOGTIME
    Decor()
    main()



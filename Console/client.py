import socket
import struct
import sqlite3, random
import hashlib , binascii, threading
import time
import ssl

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_verify_locations("server.crt")  
context.verify_mode = ssl.CERT_REQUIRED


# Khởi tạo socket client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 1234))
print("Connected to server!")

def Decor():

    content = """
    +------------------------------------------------------------------+
    |  One Time Password (OTP) Based on Advanced Encrypted Standard    |
    |            (AES) and Linear Congruential Generator(LCG)          |
    +------------------------------------------------------------------+
    """

    print(content)

def Menu():
    content = """
    +------------------------------------------------------------+
    |                                                            |
    |                 Welcome to the Menu                        |
    |                                                            |
    |    /signup <username> <password> <email>  : signup         |
    |    /signin <username> <password>           : signin         |
    |                                                            |
    +------------------------------------------------------------+
    """

    print(content)

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

def get_input(content: str):

    global NAME
    global LOGTIME

    if content:
        if content.startswith('/menu'):
            Menu()
            return None

        if content.startswith(('/signup', '/signin')):
            command, *args = content.split(' ')
            username, password, *additional_args = args
            salt = password[2:6]
            NAME = username
            hashed = binascii.hexlify(hashlib.sha256((password + salt).encode()).digest())

            if command == '/signup':
                email = additional_args[0]
                to_send = f"@signup {username} {hashed.decode()} {email}"
            else:
                timestamp = int(time.time() / 60)
                LOGTIME = str(timestamp)
                to_send = f"@signin {username} {hashed.decode()}"

            return to_send.encode()

        if content.startswith('/ecdh'):
            key = ECDH()
            to_send = f'@ecdh {binascii.hexlify(key).decode()}'
            return to_send.encode()

        if content.startswith('/otp'):
            to_send = content.replace('/otp', '@otp')
            otp = OTPGen(NAME)
            print("[POST] One Time Password (OTP)", f"Here is your OTP: {otp}")
            return to_send.encode()

        if content.startswith('/auth'):
            return content.replace('/auth', '@auth').encode()

        return content.encode()
    else:
        return None

def client_receive():
    global Check
    global server_public_key
    while True:
        try:
            content = client_socket.recv(2048).decode('utf-8')
            if(content):
                if(content.startswith('You have signed in!')):
                    Check = True
                    print(f"[POST] : {content}")
                elif(content.startswith('@pk')):
                    server_public_key = content.split(' ')[1]
                    # print(server_public_key)
                else:
                    print(f"[POST] : {content}")
            else:
                pass
        except:
            print('Error!')
            client_socket.close()
            break

def client_send():
    while True:
        user_input = get_input(input("$ "))
        if user_input:
            client_socket.send(user_input)



def ECDH():
    global secret_key

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



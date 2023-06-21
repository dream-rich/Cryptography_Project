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

# Create an SSL context with TLS 1.3 support
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_verify_locations("cert.crt")  
context.verify_mode = ssl.CERT_REQUIRED

# Khởi tạo socket client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket = ssl.wrap_socket(client_socket, ca_certs="cert.crt")
client_socket.connect(('40.81.29.50', 1234))
print("Connected to server!")

# Global variables
otp = ''

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
    |    /signin <username> <password>          : signin         |
    |    /auth   <OTP>                          : OTP            | 
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

    return public_key_der   

def generate_otp():
    global otp
    global LOGTIME
    global server_public_key
    
    # temp = server_public_key

    try:
        otp = OTPGen(server_public_key)
        print(f"[POST]: OTP generated: {otp}")

    except Exception as e:
        print(e)

def generate_new_otp():
    global otp
    global LOGTIME
    global server_public_key
    
    # temp = server_public_key
    LOGTIME = int(time.time() / 60)

    try:
        otp = OTPGen(server_public_key)
        print(f"[POST]: New OTP generated: {otp}")
    
    except Exception as e:
        print(e)
            
def OTPGen(server_public_key):
    global secret_key    
    global NAME
    global LOGTIME

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
    print(f"Shared key: {shared_key}")
    
    # cipher = Cipher(algorithms.AES(shared_key), modes.CFB(initialization_vector=shared_key[:16]), backend=default_backend())
    cipher = Cipher(algorithms.AES(shared_key), modes.GCM(shared_key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()

    print(f"Logtime: {LOGTIME}")
    print(f"Name: {NAME}")
    plaintext = NAME + str(LOGTIME)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

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
                LOGTIME = str(int(time.time() / 60))
                key = ECDH()
                to_send = f"@signin {username} {hashed.decode()} {binascii.hexlify(key).decode()}"

            return to_send.encode()

        if content.startswith('/resend'):
            return content.replace('/resend', '@resend').encode()
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
            content = client_socket.recv(4096).decode('utf-8')
            if(content):
                if(content.startswith('You have signed in!')):
                    Check = True
                    print(f"[POST]: {content}")
                elif(content.startswith('@pk')):
                    server_public_key = content.split(' ')[1]
                    print("Please enter OTP to authorize")
                    threading.Thread(target=generate_otp).start()    
                elif(content.startswith('Client requested new OTP')):
                    threading.Thread(target=generate_new_otp).start()
                elif(content.startswith('Authenticated')):
                    print(f"[POST]: {content}")
                else:
                    print(f"[POST]: {content}")
            else:
                pass
        
        except Exception as e:
            print(e)
            client_socket.close()
            break

def client_send():
    while True:
        try:
            user_input = get_input(input("$ "))
            if user_input:
                client_socket.send(user_input)
        except Exception as e:
            print(e)
            client_socket.close()
            break 

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
    Menu()
    main()



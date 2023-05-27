import socket
import struct
import sqlite3, random
import hashlib , binascii, threading
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat


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

def OTPGen(username):
    global secret_key
    global server_public_key
    global LOGTIME
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT EMAIL FROM USERS WHERE USERNAME = '{username}' "
    )
    email = cursor.fetchall()[0][0]
    conn.commit()
    conn.close()
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
    plaintext = username + email + LOGTIME

    return

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
                print(timestamp)
                to_send = f"@login {username} {hashed.decode()}"
            print(to_send)
            return to_send.encode()
        if message.startswith('/ecdh'):
            key = ECDH()
            to_send = f'@ecdh {binascii.hexlify(key).decode()}'
            return to_send.encode()
        if(message.startswith('/otp')):
            to_send = message.replace('/otp','@otp')
            OTPGen(NAME)
            return to_send.encode()
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
                    print(server_public_key)
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
    # # Chuyển đổi khóa công khai thành định dạng bytes
    # client_public_key_bytes = client_public_key.public_bytes(
    #     encoding=serialization.Encoding.DER,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # )
    # client_public_key_size = len(client_public_key_bytes)

    # # Gửi kích thước khóa công khai đến server
    # client_socket.sendall(struct.pack('!I', client_public_key_size))

    # # Gửi khóa công khai đến server
    # client_socket.sendall(client_public_key_bytes)
    # print("Public key sent")

    # # Nhận kích thước và khóa công khai của server từ server
    # server_public_key_size = struct.unpack('!I', client_socket.recv(4))[0]
    # server_public_key_bytes = client_socket.recv(server_public_key_size)
    # print("Public key received")

    # # Chuyển đổi khóa công khai của server từ bytes thành đối tượng
    # server_public_key = serialization.load_der_public_key(
    #     server_public_key_bytes,
    #     backend=default_backend()
    # )

    # # Tính toán khóa chung
    # shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
    # shared_key = HKDF(
    #     algorithm=hashes.SHA256(),
    #     length=32,
    #     salt=None,
    #     info=b'',
    # ).derive(shared_key)

    # print("Shared secret key:", shared_key.hex())
    # return shared_key

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



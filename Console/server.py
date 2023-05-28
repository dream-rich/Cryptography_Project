import socket
import struct
import sqlite3, random, threading
import time
import binascii
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
    message = """
    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    One Time Password (OTP) Based on Advanced Encrypted Standard (AES) 
                and Linear Congruential Generator(LCG)
    <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    """
    print(message)

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
# Gửi tên curve đến client
    # curve_name = "nistP256".encode('ascii')
    # client_socket.sendall(curve_name)
    # print("Curve name sent")

    # Khởi tạo khóa riêng và khóa công khai của server
    secret_key = server_private_key = ec.generate_private_key(ec.SECP256R1())
    server_public_key = server_private_key.public_key()
    server_public_key_der = server_public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return server_public_key_der

    # # Chuyển đổi khóa công khai thành định dạng bytes
    # server_public_key_bytes = server_public_key.public_bytes(
    #     encoding=serialization.Encoding.DER,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # )
    # server_public_key_size = len(server_public_key_bytes)

    # # Gửi kích thước khóa công khai đến client
    # client_socket.sendall(struct.pack('!I', server_public_key_size))

    # # Gửi khóa công khai đến client
    # client_socket.sendall(server_public_key_bytes)
    # print("Public key sent")

    # # Nhận kích thước và khóa công khai của client từ client
    # client_public_key_size = struct.unpack('!I', client_socket.recv(4))[0]
    # client_public_key_bytes = client_socket.recv(client_public_key_size)
    # print("Public key received")

    # # Chuyển đổi khóa công khai của client từ bytes thành đối tượng
    # client_public_key = serialization.load_der_public_key(
    #     client_public_key_bytes,
    #     backend=default_backend()
    # )

    # # Tính toán khóa chung
    # shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
    # shared_key = HKDF(
    #     algorithm=hashes.SHA256(),
    #     length=32,
    #     salt=None,
    #     info=b'',
    # ).derive(shared_key)

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
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT EMAIL FROM USERS WHERE USERNAME = '{username}' "
    )
    email = cursor.fetchall()[0][0]
    conn.commit()
    conn.close()
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
    plaintext = username + email + str(LOGTIME)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    # print(ciphertext)
    otp = LCG(cipher=binascii.hexlify(ciphertext).decode(),LOGTIME=LOGTIME)
    # print(otp)
    session_otp.append({client:otp})
    return

def register(username,password, email):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(
        f"INSERT INTO USERS VALUES ('{username}','{password}','{email}')"
    )
    conn.commit()
    conn.close()
    return

def login(username,password):
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
    if(message.startswith("@register")):
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        email = msg[3]
        send("Registered, please login.",client)
        register_thread = threading.Thread(target=register,args=[username,password,email])
        register_thread.start()
        return "[+] " + username + " registered!"
    if(message.startswith("@login")):
        timestamp = int(time.time()/60)
        logtime.append({client:timestamp})
        # print(timestamp)
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        logged = login(username,password)
        if(logged):
        #   session.append({client:id})
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
          message = client.recv(4096)
          msg = handle(message=message.decode(),client=client)
          if(msg):
            print(f"[LOG] : {msg}")   
      except:
          index = clients.index(client)
          clients.remove(client)
          client.close()
          break
        
def LISTEN():
    while True:
        client, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client,args=(client,))
        thread.start()
        clients.append(client)

def main():
    LISTEN()
if __name__=="__main__":
    global secret_key
    Decor()
    main()


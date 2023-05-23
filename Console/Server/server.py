import socket
import struct
import sqlite3, random, threading
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# Khởi tạo socket server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 1234))
server_socket.listen(1)
clients = []
session = []
print("Waiting for client connection...")

# Chấp nhận kết nối từ client
client_socket, addr = server_socket.accept()
print("Client connected!")

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


def ECDH():
# Gửi tên curve đến client
    curve_name = "nistP256".encode('ascii')
    client_socket.sendall(curve_name)
    print("Curve name sent")

    # Khởi tạo khóa riêng và khóa công khai của server
    server_private_key = ec.generate_private_key(ec.SECP256R1())
    server_public_key = server_private_key.public_key()

    # Chuyển đổi khóa công khai thành định dạng bytes
    server_public_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    server_public_key_size = len(server_public_key_bytes)

    # Gửi kích thước khóa công khai đến client
    client_socket.sendall(struct.pack('!I', server_public_key_size))

    # Gửi khóa công khai đến client
    client_socket.sendall(server_public_key_bytes)
    print("Public key sent")

    # Nhận kích thước và khóa công khai của client từ client
    client_public_key_size = struct.unpack('!I', client_socket.recv(4))[0]
    client_public_key_bytes = client_socket.recv(client_public_key_size)
    print("Public key received")

    # Chuyển đổi khóa công khai của client từ bytes thành đối tượng
    client_public_key = serialization.load_der_public_key(
        client_public_key_bytes,
        backend=default_backend()
    )

    # Tính toán khóa chung
    shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
    shared_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
    ).derive(shared_key)

    print("Shared secret key:", shared_key.hex())

def register(username,password,email):
        conn = sqlite3.connect('data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            return False
        else:
            cursor.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, password, email))
            conn.commit()
            conn.close()
            return True

def login(username,password):
  conn = sqlite3.connect('data.db')
  c = conn.cursor()
  c.execute(
    f"SELECT PASSWORD,CUSTOMERID FROM CUSTOMERS WHERE USERNAME = '{username}'"
  )
  sv_password,id = c.fetchall()[0]
  conn.commit()
  conn.close()
  if(sv_password == password):
     return True,id
  else:
     return False,None
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
        username = ""
        msg = message.split(' ')
        username = msg[1]
        password = msg[2]
        logged,id = login(username,password)
        if(logged):
           session.append({client:id})
           send("Logged in.",client)
           return f"{username} logged in"
        else:
           send("Wrong password",client)
           return None
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
    Decor()
    main()

client_socket.close()
server_socket.close()

import socket
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# Khởi tạo socket client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 1234))
print("Connected to server!")

# Nhận tên curve từ server
curve_name = client_socket.recv(8).decode('ascii')
print("Curve name received")

# Khởi tạo khóa riêng và khóa công khai của client
client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()

# Chuyển đổi khóa công khai thành định dạng bytes
client_public_key_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
client_public_key_size = len(client_public_key_bytes)

# Gửi kích thước khóa công khai đến server
client_socket.sendall(struct.pack('!I', client_public_key_size))

# Gửi khóa công khai đến server
client_socket.sendall(client_public_key_bytes)
print("Public key sent")

# Nhận kích thước và khóa công khai của server từ server
server_public_key_size = struct.unpack('!I', client_socket.recv(4))[0]
server_public_key_bytes = client_socket.recv(server_public_key_size)
print("Public key received")

# Chuyển đổi khóa công khai của server từ bytes thành đối tượng
server_public_key = serialization.load_der_public_key(
    server_public_key_bytes,
    backend=default_backend()
)

# Tính toán khóa chung
shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
shared_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'',
).derive(shared_key)

print("Shared secret key:", shared_key.hex())

client_socket.close()


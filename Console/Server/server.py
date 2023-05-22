import socket
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# Khởi tạo socket server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 1234))
server_socket.listen(1)
print("Waiting for client connection...")

# Chấp nhận kết nối từ client
client_socket, addr = server_socket.accept()
print("Client connected!")

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

client_socket.close()
server_socket.close()

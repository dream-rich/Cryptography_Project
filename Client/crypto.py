from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    serialized_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return serialized_private_key.decode('utf-8'), serialized_public_key.decode('utf-8')

def derive_shared_key(private_key_data, peer_public_key_data):
    private_key = serialization.load_pem_private_key(
        private_key_data.encode('utf-8'),
        password=None
    )
    peer_public_key = serialization.load_pem_public_key(
        peer_public_key_data.encode('utf-8')
    )
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key.hex()

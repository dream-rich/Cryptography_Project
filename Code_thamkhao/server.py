from flask import Flask, render_template, request, jsonify
import base64
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sqlite3
import string
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# Generate ECDH key pair for the server
server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
server_public_key = server_private_key.public_key()

# Database initialization
DATABASE = 'database.db'
conn = sqlite3.connect(DATABASE)
c = conn.cursor()
c.execute("CREATE TABLE IF NOT EXISTS otp (ciphertext TEXT, otp TEXT)")
conn.commit()

# Sheet for OTP generation
sheet = string.ascii_letters + string.digits

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    # Receive the client's public key
    client_public_key_base64 = request.form['public_key']
    client_public_key_pem = base64.b64decode(client_public_key_base64)

    # Deserialize the client's public key
    client_public_key = serialization.load_pem_public_key(client_public_key_pem, backend=default_backend())

    # Generate shared secret key using ECDH
    shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)

    # Derive a 256-bit secret key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
        backend=default_backend()
    ).derive(shared_key)

    # Store the derived key securely (e.g., in a secure enclave or key management system)

    return jsonify({'success': True})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    # Retrieve the plaintext from the client
    username = request.form['username']
    email = request.form['email']
    access_time = request.form['access_time']

    # Concatenate the plaintext
    plaintext = f"{username},{email},{access_time}"

    # Generate shared secret key using ECDH (same as in generate_key route)

    # Derive a 256-bit secret key using HKDF (same as in generate_key route)

    # Encrypt the plaintext using AES with the derived key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

    # Store the ciphertext in the database
    c.execute("INSERT INTO otp (ciphertext) VALUES (?)", (base64.b64encode(ciphertext).decode('utf-8'),))
    conn.commit()

    return jsonify({'success': True})
Sheet for OTP generation
sheet = string.ascii_letters + string.digits

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    client_public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return jsonify({'public_key': base64.b64encode(client_public_key_pem).decode('utf-8')})

@app.route('/save_data', methods=['POST'])
def save_data():
    username = request.form['username']
    email = request.form['email']
    access_time = str(int(time.time()))

    # Perform ECDH key exchange with the server's public key
    server_public_key_pem = base64.b64decode(request.form['server_public_key'])
    server_public_key = serialization.load_pem_public_key(server_public_key_pem, backend=default_backend())

    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
        backend=default_backend()
    ).derive(shared_secret)

    # Encrypt plaintext using AES with the derived key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    plaintext = f'{username},{email},{access_time}'.encode('utf-8')
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save the ciphertext to the database
    c.execute("INSERT INTO otp (ciphertext, otp) VALUES (?, ?)", (base64.b64encode(ciphertext).decode('utf-8'), ''))
    conn.commit()

    return jsonify({'ciphertext': base64.b64encode(ciphertext).decode('utf-8'), 'iv': base64.b64encode(iv).decode('utf-8')})

@app.route('/get_otp', methods=['POST'])
def get_otp():
    # Retrieve the ciphertext from the database
    c.execute("SELECT ciphertext FROM otp ORDER BY rowid DESC LIMIT 1")
    result = c.fetchone()
    ciphertext = base64.b64decode(result[0])

    # Decrypt the ciphertext using AES with the derived key
    c.execute("SELECT otp FROM otp ORDER BY rowid DESC LIMIT 1")
    result = c.fetchone()
    otp = result[0]

    return jsonify({'ciphertext': base64.b64encode(ciphertext).decode('utf-8'), 'otp': otp})

@app.route('/generate_otp', methods=['POST'])
def generate_otp():
    # Retrieve the ciphertext from the database
    c.execute("SELECT ciphertext FROM otp ORDER BY rowid DESC LIMIT 1")
    result = c.fetchone()
    ciphertext = base64.b64decode(result[0])

    # Decrypt the ciphertext using AES with the derived key
    c.execute("SELECT otp FROM otp ORDER BY rowid DESC LIMIT 1")
    result = c.fetchone()
    otp = result[0]

    # Generate OTP using LCG
    timestamp = int(time.time())
    seed = timestamp % len(sheet)
    a, c, m = 1664525, 1013904223, len(sheet)
    for _ in range(6):
        seed = (a * seed + c) % m
        if seed >= len(sheet):
            seed %= len(sheet)
        otp += str(sheet[seed]) if sheet[seed].isdigit() else str(ord(sheet[seed]))

    # Update the OTP in the database
    c.execute("UPDATE otp SET otp = ? WHERE ciphertext = ?", (otp, base64.b64encode(ciphertext).decode('utf-8')))
    conn.commit()

    return jsonify({'otp': otp})
if __name__ == '__main__':
    app.run(port=5000)

from flask import Flask, render_template, request, jsonify
import requests
import os
import time

app = Flask(__name__)

# Thông tin cấu hình ECDH và AES
EC_KEY_SIZE = 256
AES_KEY_SIZE = 32
AES_IV_SIZE = 16
LCG_A = 1664525
LCG_C = 1013904223
LCG_M = 2 ** 32

# Thông tin cấu hình server
SERVER_URL = 'http://server-ip:server-port'

# Đường dẫn đến file sheet
SHEET_FILE = 'sheet.txt'

# Đường dẫn đến file SQLite database
DATABASE_FILE = 'database.db'

# Tạo table otp trong database
def create_otp_table():
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS otp
                 (ciphertext BLOB, otp TEXT)''')
    conn.commit()
    conn.close()

# Route để hiển thị trang chủ
@app.route('/')
def home():
    return render_template('home.html')

# Route để gửi yêu cầu trao đổi khóa và tạo OTP
@app.route('/generate_otp', methods=['POST'])
def generate_otp():
    # Lấy thông tin từ form
    username = request.form['username']
    email = request.form['email']
    access_time = time.time()

    # Gửi yêu cầu trao đổi khóa ECDH với server
    response = requests.post(f'{SERVER_URL}/generate_key')

    # Nhận public key từ server
    server_public_key = response.json()['public_key']

    # Tạo khóa riêng ECDH
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_key = private_key.exchange(ec.ECDH(), load_pem_public_key(server_public_key.encode(), default_backend()))

    # Tạo khóa AES từ shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE + AES_IV_SIZE,
        salt=None,
        info=b'',
        backend=default_backend()
    ).derive(shared_key)

    # Mã hóa plaintext bằng AES
    plaintext = f'{username},{email},{access_time}'.encode()
    cipher = Cipher(algorithms.AES(derived_key[:AES_KEY_SIZE]), modes.CBC(derived_key[AES_KEY_SIZE:]), default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Lưu ciphertext vào database
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO otp (ciphertext) VALUES (?)", (sqlite3.Binary(ciphertext),))
    conn.commit()
    conn.close()

    # Đọc file sheet
    with open(SHEET_FILE, 'r') as file:
        sheet = file.read().strip()

    # Tạo OTP từ sheet và seed
    otp = generate_otp_from_sheet(sheet, access_time)

    return jsonify({'success': True, 'otp': otp})

# Hàm tạo OTP từ sheet và seed
def generate_otp_from_sheet(sheet, seed):
    otp = ''
    for _ in range(6):
        seed = (LCG_A * seed + LCG_C) % LCG_M
        index = seed % len(sheet)
        char = sheet[index]
        if char.isalpha():
            otp += str(ord(char))
        else:
            otp += char
    return otp

if __name__ == '__main__':
    # Kiểm tra nếu file database chưa tồn tại thì tạo mới
    if not os.path.exists(DATABASE_FILE):
        create_otp_table()

    app.run()

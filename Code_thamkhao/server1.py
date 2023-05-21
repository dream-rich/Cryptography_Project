from flask import Flask, request, jsonify
import os
import sqlite3
import time

app = Flask(__name__)

# Thông tin cấu hình ECDH và AES
EC_KEY_SIZE = 256
AES_KEY_SIZE = 32
AES_IV_SIZE = 16

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

# Route để nhận yêu cầu trao đổi khóa
@app.route('/generate_key', methods=['POST'])
def generate_key():
    # Tạo khóa riêng ECDH
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return jsonify({'public_key': public_key.decode()})

# Route để xác thực OTP
@app.route('/authenticate_otp', methods=['POST'])
def authenticate_otp():
    # Lấy OTP từ request
    otp = request.json['otp']

    # Lấy ciphertext từ database dựa trên OTP
    conn = sqlite3.connect(DATABASE_FILE)
    c = conn.cursor()
    c.execute("SELECT ciphertext FROM otp WHERE otp = ?", (otp,))
    result = c.fetchone()
    conn.close()

    if result is not None:
        ciphertext = result[0]
        
        # Đọc file sheet
        with open(SHEET_FILE, 'r') as file:
            sheet = file.read().strip()

        # Lấy seed từ thời gian hiện tại
        seed = int(time.time()) % len(sheet)

        # Tạo OTP từ sheet và seed
        generated_otp = generate_otp_from_sheet(sheet, seed)

        if generated_otp == otp:
            return jsonify({'success': True})

    return jsonify({'success': False})

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

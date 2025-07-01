# BAITAPLON/app.py

from flask import Flask, render_template, request, redirect, url_for, session, flash
import hashlib
import sqlite3
import os
from datetime import datetime
import secrets # For generating random salt
from base64 import b64encode, b64decode # For Base64 encoding/decoding binary data
from Crypto.Cipher import DES3 # For Triple DES encryption/decryption
from Crypto.Random import get_random_bytes # For generating IV for DES3
from Crypto.Util.Padding import pad, unpad # For PKCS7 padding

app = Flask(__name__)
# Đảm bảo bạn thay đổi khóa này thành một chuỗi ngẫu nhiên mạnh mẽ trong thực tế
app.secret_key = 'your_another_super_secret_key_here_for_security'

DATABASE = 'database.db'
MAX_FAILED_ATTEMPTS = 5 # Số lần đăng nhập sai tối đa trước khi khóa tài khoản

# --- Cấu hình Triple DES ---
# Đây là key cho DES3. TRONG THỰC TẾ, ĐÂY PHẢI LÀ MỘT KHÓA MẠNH, ĐƯỢC QUẢN LÝ AN TOÀN
# Độ dài key DES3 phải là 16 hoặc 24 bytes. Sử dụng 24 bytes cho 3DES EDE.
# Đảm bảo chuỗi này có chính xác 24 ký tự.
DES3_KEY = b'SixteenByteKeyFor3DES_24' # Ví dụ: chuỗi 24 ký tự

# Kiểm tra độ dài khóa
if len(DES3_KEY) not in [16, 24]:
    raise ValueError("DES3_KEY must be 16 or 24 bytes long.")

# Block size for DES3 (always 8 bytes)
BS = DES3.block_size

# --- Hàm hỗ trợ cơ sở dữ liệu ---
def get_db():
    """Establishes a database connection and sets row_factory for dict-like access."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row # Cho phép truy cập cột bằng tên
    return conn

def init_db():
    """
    Initializes the database: creates tables if they don't exist,
    adds new columns if missing, and creates fixed admin accounts.
    """
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # 1. Tạo hoặc cập nhật bảng 'users'
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,               -- Cột cho salt ngẫu nhiên
                encrypted_password TEXT NOT NULL, -- Cột cho hash cuối cùng đã mã hóa bằng 3DES
                role TEXT NOT NULL DEFAULT 'user',
                failed_login_attempts INTEGER DEFAULT 0,
                is_locked INTEGER DEFAULT 0,      -- 0 for FALSE (không bị khóa), 1 for TRUE (bị khóa)
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, -- Cột cho thời gian tạo
                full_name TEXT DEFAULT '',        -- Thêm cột Họ và tên
                date_of_birth TEXT DEFAULT '',    -- Thêm cột Ngày sinh (format YYYY-MM-DD)
                address TEXT DEFAULT '',          -- Thêm cột Địa chỉ
                phone_number TEXT DEFAULT ''      -- Thêm cột Số điện thoại
            )
        ''')
        db.commit()

        # Kiểm tra và thêm cột nếu chúng chưa tồn tại (cho trường hợp DB đã có từ trước)
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'salt' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN salt TEXT")
            db.commit()
            print("Cột 'salt' đã được thêm vào bảng 'users'.")
        
        if 'encrypted_password' not in columns and 'password_hash' in columns:
            cursor.execute("ALTER TABLE users RENAME COLUMN password_hash TO encrypted_password")
            db.commit()
            print("Cột 'password_hash' đã được đổi tên thành 'encrypted_password'.")
        elif 'encrypted_password' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN encrypted_password TEXT")
            db.commit()
            print("Cột 'encrypted_password' đã được thêm vào bảng 'users'.")

        if 'failed_login_attempts' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0")
            db.commit()
            print("Cột 'failed_login_attempts' đã được thêm vào bảng 'users'.")
        
        if 'is_locked' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN is_locked INTEGER DEFAULT 0")
            db.commit()
            print("Cột 'is_locked' đã được thêm vào bảng 'users'.")
        
        if 'created_at' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP")
            db.commit()
            print("Cột 'created_at' đã được thêm vào bảng 'users'.")

        if 'full_name' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT DEFAULT ''")
            db.commit()
            print("Cột 'full_name' đã được thêm vào bảng 'users'.")
        if 'date_of_birth' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN date_of_birth TEXT DEFAULT ''")
            db.commit()
            print("Cột 'date_of_birth' đã được thêm vào bảng 'users'.")
        if 'address' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN address TEXT DEFAULT ''")
            db.commit()
            print("Cột 'address' đã được thêm vào bảng 'users'.")
        if 'phone_number' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN phone_number TEXT DEFAULT ''")
            db.commit()
            print("Cột 'phone_number' đã được thêm vào bảng 'users'.")
            
        # 2. Tạo bảng lịch sử đăng nhập
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL, -- 'success', 'failure (wrong password)', 'failure (locked)', v.v.
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        db.commit()

        # 3. Thêm các tài khoản admin cố định nếu chưa có
        fixed_admin_accounts = [
            {'username': 'admin', 'password': 'admin_password', 'full_name': 'Admin Hệ thống'}, # Admin mặc định
            {'username': 'thanh', 'password': '1234', 'full_name': 'Nguyễn Văn Thanh'},
            {'username': 'kien', 'password': '1234', 'full_name': 'Lê Hoàng Kiên'},
            {'username': 'hoa', 'password': '1234', 'full_name': 'Trần Thị Hoa'}
        ]

        for account in fixed_admin_accounts:
            username = account['username']
            password = account['password']
            full_name = account['full_name']

            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            if cursor.fetchone() is None:
                new_salt = generate_salt()
                combined_hash = hash_password_and_username_with_salt(password, username, new_salt)
                encrypted_password_data = encrypt_data_des3(combined_hash.encode('utf-8'))
                
                cursor.execute("INSERT INTO users (username, salt, encrypted_password, role, failed_login_attempts, is_locked, created_at, full_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                               (username, new_salt, encrypted_password_data, 'admin', 0, 0, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), full_name))
                db.commit()
                print(f"Tài khoản admin '{username}' đã được tạo cố định.")
            else:
                print(f"Tài khoản admin '{username}' đã tồn tại, bỏ qua tạo mới.")
        db.close()

# --- Hàm băm và mã hóa mật khẩu theo yêu cầu đề bài ---

def generate_salt(length=16):
    """Tạo salt ngẫu nhiên."""
    return secrets.token_hex(length)

def hash_data_sha256(data):
    """Băm dữ liệu bằng SHA-256."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def hash_password_and_username_with_salt(password, username, salt):
    """
    Thực hiện các bước băm mật khẩu theo yêu cầu:
    1. Băm password + salt
    2. Băm username
    3. Kết hợp hai giá trị hash và băm lại
    """
    # Bước 1: Băm password + salt
    password_salted_hash = hash_data_sha256(password + salt)
    
    # Bước 2: Băm username
    username_hash = hash_data_sha256(username)
    
    # Bước 3: Kết hợp hai giá trị hash và băm lại
    combined_hash_input = password_salted_hash + username_hash
    final_hash = hash_data_sha256(combined_hash_input)
    
    return final_hash

def encrypt_data_des3(raw_data_bytes):
    """
    Mã hóa dữ liệu bằng Triple DES ở chế độ CBC với PKCS7 padding.
    Trả về IV + ciphertext, được mã hóa Base64 dưới dạng chuỗi.
    """
    raw_data_padded = pad(raw_data_bytes, BS)
    iv = get_random_bytes(BS) # Initialization Vector
    cipher = DES3.new(DES3_KEY, DES3.MODE_CBC, iv)
    encrypted = cipher.encrypt(raw_data_padded)
    # Trả về IV + dữ liệu mã hóa, mã hóa Base64 để lưu vào DB (dạng text)
    return b64encode(iv + encrypted).decode('utf-8')

def decrypt_data_des3(enc_data_str):
    """
    Giải mã dữ liệu Triple DES đã được mã hóa Base64.
    Trích xuất IV, giải mã và bỏ padding. Trả về plaintext gốc dưới dạng chuỗi.
    """
    enc_data_bytes = b64decode(enc_data_str.encode('utf-8'))
    iv = enc_data_bytes[:BS] # Lấy IV từ đầu chuỗi
    encrypted = enc_data_bytes[BS:]
    cipher = DES3.new(DES3_KEY, DES3.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted)
    return unpad(decrypted_padded, BS).decode('utf-8')

# --- Chạy hàm khởi tạo DB khi ứng dụng bắt đầu ---
if not os.path.exists(DATABASE):
    print("Database chưa tồn tại. Đang tạo và thêm tài khoản admin cố định.")
    init_db()
else:
    print("Database đã tồn tại. Đang kiểm tra và thêm các tài khoản admin cố định còn thiếu, cập nhật cấu trúc bảng.")
    init_db()

# --- Các route của ứng dụng ---

@app.route('/', methods=['GET'])
def index():
    """Renders the login/registration page or redirects if already logged in."""
    if 'username' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    """Handles user registration."""
    username = request.form['username']
    password = request.form['password']

    if not username or not password:
        flash('Vui lòng điền đầy đủ tên đăng nhập và mật khẩu.', 'error')
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    try:
        new_salt = generate_salt()
        final_hash_result = hash_password_and_username_with_salt(password, username, new_salt)
        encrypted_password_data = encrypt_data_des3(final_hash_result.encode('utf-8'))
        
        # Khi đăng ký, tài khoản được tạo với is_locked = 0 (FALSE - không bị khóa)
        cursor.execute("INSERT INTO users (username, salt, encrypted_password, role, failed_login_attempts, is_locked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (username, new_salt, encrypted_password_data, 'user', 0, 0, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        db.commit()
        flash('Đăng ký thành công! Bạn có thể đăng nhập ngay bây giờ.', 'success')
    except sqlite3.IntegrityError:
        flash('Tên đăng nhập đã tồn tại. Vui lòng chọn tên khác.', 'error')
    except Exception as e:
        flash(f'Đã xảy ra lỗi khi đăng ký: {e}', 'error')
        print(f"Error during registration: {e}")
    finally:
        db.close()
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    """Handles user login."""
    username = request.form['username']
    password = request.form['password']
    selected_role = request.form.get('role_type')
    ip_address = request.remote_addr 

    db = get_db()
    cursor = db.cursor()
    
    user_id = None
    login_status = 'failure (unknown error)'

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        user_id = user['id']
        # Kiểm tra nếu tài khoản đã bị khóa (is_locked = 1)
        if user['is_locked'] == 1:
            flash(f'Tài khoản "{username}" của bạn đã bị khóa do đăng nhập sai quá nhiều lần. Vui lòng liên hệ quản trị viên để mở khóa.', 'error')
            login_status = 'failure (locked)'
        else:
            stored_salt = user['salt']
            stored_encrypted_password = user['encrypted_password']

            input_combined_hash = hash_password_and_username_with_salt(password, username, stored_salt)
            
            try:
                decrypted_stored_hash = decrypt_data_des3(stored_encrypted_password)
            except Exception as e:
                flash('Lỗi giải mã mật khẩu. Vui lòng liên hệ quản trị viên.', 'error')
                print(f"Decryption error for user {username}: {e}")
                login_status = 'failure (decryption error)'
                
            if login_status != 'failure (decryption error)': # Chỉ so sánh nếu không có lỗi giải mã
                if decrypted_stored_hash == input_combined_hash:
                    if user['role'] == selected_role:
                        # Đăng nhập thành công
                        session['username'] = user['username']
                        session['role'] = user['role']
                        # Đặt lại số lần đăng nhập sai về 0 và is_locked về 0 (FALSE) khi đăng nhập thành công
                        cursor.execute("UPDATE users SET failed_login_attempts = 0, is_locked = 0 WHERE username = ?", (username,))
                        db.commit()
                        login_status = 'success'
                        flash(f'Chào mừng, {user["username"]}!', 'success')
                    else:
                        # Mật khẩu đúng nhưng vai trò chọn sai
                        flash(f'Tên đăng nhập này không có vai trò "{selected_role}". Vui lòng chọn đúng vai trò hoặc liên hệ quản trị viên.', 'error')
                        # Tăng số lần đăng nhập sai
                        cursor.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?", (username,))
                        db.commit()
                        login_status = 'failure (wrong role)'
                else:
                    # Mật khẩu sai
                    flash('Tên đăng nhập hoặc mật khẩu không đúng.', 'error')
                    # Tăng số lần đăng nhập sai
                    cursor.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE username = ?", (username,))
                    db.commit()
                    login_status = 'failure (wrong password)'
            
            # Sau khi cố gắng đăng nhập (trừ trường hợp tài khoản không tồn tại hoặc đã bị khóa từ trước),
            # kiểm tra và khóa tài khoản nếu đạt đến số lần đăng nhập sai tối đa (MAX_FAILED_ATTEMPTS)
            if login_status != 'success' and login_status != 'failure (locked)':
                cursor.execute("SELECT failed_login_attempts FROM users WHERE username = ?", (username,))
                current_attempts = cursor.fetchone()['failed_login_attempts']
                if current_attempts >= MAX_FAILED_ATTEMPTS:
                    # Cập nhật is_locked = 1 (TRUE) khi tài khoản bị khóa
                    cursor.execute("UPDATE users SET is_locked = 1 WHERE username = ?", (username,))
                    db.commit()
                    flash(f'Tài khoản "{username}" đã bị khóa do đăng nhập sai quá {MAX_FAILED_ATTEMPTS} lần. Vui lòng liên hệ quản trị viên.', 'error')
                    login_status = 'failure (locked after attempts)'
                elif login_status != 'failure (decryption error)': # Chỉ hiển thị số lần thử còn lại nếu không phải lỗi giải mã
                    flash(f'Bạn còn {MAX_FAILED_ATTEMPTS - current_attempts} lần thử.', 'info')

    else:
        # Tên đăng nhập không tồn tại
        flash('Tên đăng nhập hoặc mật khẩu không đúng.', 'error')
        login_status = 'failure (non-existent user)'
    
    # Ghi log vào bảng login_history
    cursor.execute("INSERT INTO login_history (user_id, username, timestamp, status, ip_address) VALUES (?, ?, ?, ?, ?)",
                   (user_id, username, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), login_status, ip_address))
    db.commit()
    
    db.close()
    
    if 'username' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    """Handles user logout."""
    session.pop('username', None)
    session.pop('role', None)
    flash('Bạn đã đăng xuất.', 'info')
    return redirect(url_for('index'))

# --- Giao diện Người dùng ---
@app.route('/dashboard')
def user_dashboard():
    """Renders the user dashboard, requires user role."""
    if 'username' not in session or session['role'] != 'user':
        flash('Bạn cần đăng nhập với tài khoản người dùng để truy cập.', 'error')
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    # Lấy tất cả thông tin của người dùng hiện tại
    cursor.execute("SELECT id, username, role, full_name, date_of_birth, address, phone_number FROM users WHERE username = ?", (session['username'],))
    user_info = cursor.fetchone()
    db.close()

    if not user_info:
        flash('Không tìm thấy thông tin người dùng.', 'error')
        session.pop('username', None) # Xóa session nếu không tìm thấy user
        session.pop('role', None)
        return redirect(url_for('index'))

    return render_template('dashboard.html',
                           current_user=session['username'],
                           current_role=session['role'],
                           user_info=user_info) # Truyền toàn bộ thông tin người dùng

@app.route('/update_profile', methods=['POST'])
def update_profile():
    """Handles updating user profile information (excluding username and password)."""
    if 'username' not in session or session['role'] not in ['user', 'admin']:
        flash('Bạn cần đăng nhập để thực hiện chức năng này.', 'error')
        return redirect(url_for('index'))

    full_name = request.form.get('full_name', '')
    date_of_birth = request.form.get('date_of_birth', '')
    address = request.form.get('address', '')
    phone_number = request.form.get('phone_number', '')

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE users SET full_name = ?, date_of_birth = ?, address = ?, phone_number = ? WHERE username = ?",
                       (full_name, date_of_birth, address, phone_number, session['username']))
        db.commit()
        flash('Thông tin cá nhân đã được cập nhật thành công!', 'success')
    except Exception as e:
        flash(f'Đã xảy ra lỗi khi cập nhật thông tin: {e}', 'error')
        print(f"Error updating profile for {session['username']}: {e}")
    finally:
        db.close()
    return redirect(url_for('user_dashboard'))


@app.route('/change_password', methods=['POST'])
def change_password():
    """Handles password change for logged-in users."""
    if 'username' not in session:
        flash('Bạn cần đăng nhập để thực hiện chức năng này.', 'error')
        return redirect(url_for('index'))

    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_new_password = request.form['confirm_new_password']

    if not old_password or not new_password or not confirm_new_password:
        flash('Vui lòng điền đầy đủ các trường mật khẩu.', 'error')
        return redirect(url_for('user_dashboard'))

    if new_password != confirm_new_password:
        flash('Mật khẩu mới và xác nhận mật khẩu không khớp.', 'error')
        return redirect(url_for('user_dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (session['username'],))
    user = cursor.fetchone()

    if user:
        stored_salt = user['salt']
        stored_encrypted_password = user['encrypted_password']
        
        input_old_combined_hash = hash_password_and_username_with_salt(old_password, session['username'], stored_salt)
        
        try:
            decrypted_stored_hash = decrypt_data_des3(stored_encrypted_password)
        except Exception as e:
            flash('Lỗi giải mã mật khẩu cũ. Vui lòng liên hệ quản trị viên.', 'error')
            print(f"Decryption error during password change for user {session['username']}: {e}")
            db.close()
            return redirect(url_for('user_dashboard'))

        if decrypted_stored_hash == input_old_combined_hash:
            # Mật khẩu cũ đúng
            new_salt = generate_salt() # Tạo salt MỚI cho mật khẩu mới
            new_combined_hash = hash_password_and_username_with_salt(new_password, session['username'], new_salt)
            encrypted_new_password_data = encrypt_data_des3(new_combined_hash.encode('utf-8'))

            # Cập nhật salt, mật khẩu đã mã hóa, và đặt lại số lần đăng nhập sai về 0, is_locked về 0 (FALSE)
            cursor.execute("UPDATE users SET salt = ?, encrypted_password = ?, failed_login_attempts = 0, is_locked = 0 WHERE username = ?",
                           (new_salt, encrypted_new_password_data, session['username']))
            db.commit()
            flash('Mật khẩu đã được thay đổi thành công!', 'success')
        else:
            flash('Mật khẩu cũ không đúng.', 'error')
    else:
        flash('Không tìm thấy người dùng.', 'error') 
    db.close()
    return redirect(url_for('user_dashboard'))

# --- Giao diện Admin ---
@app.route('/admin')
def admin_dashboard():
    """Renders the admin panel, requires admin role."""
    if 'username' not in session or session['role'] != 'admin':
        flash('Bạn không có quyền truy cập trang quản trị.', 'error')
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, role, is_locked, failed_login_attempts, created_at, encrypted_password FROM users")
    users_data = cursor.fetchall() # Lấy tất cả dữ liệu người dùng

    # Tạo một danh sách mới để chứa dữ liệu người dùng đã được xử lý (bao gồm hash đã giải mã)
    users_list_processed = []
    for user in users_data:
        user_dict = dict(user) # Chuyển Row object thành dict để dễ dàng thêm key mới
        try:
            # Giải mã encrypted_password để lấy hash cuối cùng
            user_dict['decrypted_hash'] = decrypt_data_des3(user['encrypted_password'])
        except Exception as e:
            user_dict['decrypted_hash'] = "Lỗi giải mã" # Xử lý lỗi nếu không giải mã được
            print(f"Error decrypting password for user {user['username']}: {e}")
        users_list_processed.append(user_dict)


    cursor.execute("SELECT lh.id, lh.username, lh.timestamp, lh.status, lh.ip_address FROM login_history lh ORDER BY lh.timestamp DESC")
    login_logs = cursor.fetchall()
    
    db.close()

    return render_template('admin_panel.html',
                           current_user=session['username'],
                           current_role=session['role'],
                           users_list=users_list_processed, # Truyền danh sách đã xử lý
                           login_logs=login_logs)

@app.route('/admin_action', methods=['POST'])
def admin_action():
    """Handles various admin actions (add, delete, reset password, change role, unlock)."""
    if 'username' not in session or session['role'] != 'admin':
        flash('Bạn không có quyền thực hiện hành động này.', 'error')
        return redirect(url_for('index'))

    action = request.form['action']
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')

    db = get_db()
    cursor = db.cursor()

    if action == 'add_user':
        if not username or not password or not role:
            flash('Vui lòng điền đầy đủ thông tin để thêm người dùng.', 'error')
        else:
            try:
                new_salt = generate_salt()
                final_hash_result = hash_password_and_username_with_salt(password, username, new_salt)
                encrypted_password_data = encrypt_data_des3(final_hash_result.encode('utf-8'))
                
                # Khi thêm người dùng mới, is_locked được đặt là 0 (FALSE)
                cursor.execute("INSERT INTO users (username, salt, encrypted_password, role, failed_login_attempts, is_locked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                               (username, new_salt, encrypted_password_data, role, 0, 0, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                db.commit()
                flash(f'Người dùng "{username}" đã được thêm thành công.', 'success')
            except sqlite3.IntegrityError:
                flash('Tên đăng nhập đã tồn tại.', 'error')
            except Exception as e:
                flash(f'Đã xảy ra lỗi khi thêm người dùng: {e}', 'error')
                print(f"Error adding user: {e}")

    elif action == 'delete_user':
        if user_id:
            current_user_id_query = cursor.execute("SELECT id FROM users WHERE username = ?", (session['username'],)).fetchone()
            if current_user_id_query and str(current_user_id_query['id']) == user_id:
                flash('Bạn không thể tự xóa tài khoản của mình.', 'error')
            else:
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                cursor.execute("DELETE FROM login_history WHERE user_id = ?", (user_id,))
                db.commit()
                flash('Người dùng và lịch sử đăng nhập liên quan đã được xóa.', 'success')
    
    elif action == 'reset_password':
        if user_id and password:
            user_to_reset = cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
            if user_to_reset:
                reset_username = user_to_reset['username']
                new_salt = generate_salt()
                new_combined_hash = hash_password_and_username_with_salt(password, reset_username, new_salt)
                encrypted_new_password_data = encrypt_data_des3(new_combined_hash.encode('utf-8'))

                # Khi đặt lại mật khẩu, đặt lại số lần đăng nhập sai về 0 và is_locked về 0 (FALSE)
                cursor.execute("UPDATE users SET salt = ?, encrypted_password = ?, failed_login_attempts = 0, is_locked = 0 WHERE id = ?",
                               (new_salt, encrypted_new_password_data, user_id)) 
                db.commit()
                flash('Mật khẩu người dùng đã được đặt lại và tài khoản đã được mở khóa.', 'success')
            else:
                flash('Không tìm thấy người dùng để đặt lại mật khẩu.', 'error')
    
    elif action == 'change_role':
        if user_id and role:
            cursor.execute("UPDATE users SET role = ? WHERE id = ?",
                           (role, user_id))
            db.commit()
            flash('Vai trò người dùng đã được cập nhật.', 'success')
    
    elif action == 'unlock_account':
        if user_id:
            # Khi mở khóa tài khoản, đặt is_locked về 0 (FALSE) và reset số lần đăng nhập sai
            cursor.execute("UPDATE users SET is_locked = 0, failed_login_attempts = 0 WHERE id = ?", (user_id,))
            db.commit()
            flash('Tài khoản đã được mở khóa thành công!', 'success')
    
    db.close()
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)

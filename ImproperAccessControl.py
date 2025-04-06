from flask import Flask, request, render_template, session, jsonify, redirect, url_for, flash
from functools import wraps
from datetime import datetime
import sqlite3, hashlib, requests, secrets, logging, os, random, string

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

lab_type = "AccountTakeover"
lab_name = "ImproperAccessControlLab"

ImproperAccessControl = Flask(__name__)
ImproperAccessControl.secret_key = "vulnerable_lab_by_IHA089"

flag_data = {}
req_res_data = {}

def generate_flag(length=10):
    charset = string.ascii_letters + string.digits
    random_string = ''.join(random.choices(charset, k=length))
    return random_string

def create_database():
    db_path = os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        gmail TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        active TINYINT(1) DEFAULT 0,
        code TEXT NOT NULL
    )
    ''')

    numb = random.randint(100, 999)
    passw = "admin@"+str(numb)
    passw_hash = hashlib.md5(passw.encode()).hexdigest()
    query = "INSERT INTO users (gmail, username, password, active, code) VALUES ('admin@iha089.org', 'admin', '"+passw_hash+"', '1', '45AEDF32')"
    cursor.execute(query)

    cursor.execute('''
    CREATE TABLE token_info(
        gmail TEXT NOT NULL,
        token TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    conn.commit()
    conn.close()

def generate_code():
    first_two = ''.join(random.choices(string.digits, k=2))
    next_four = ''.join(random.choices(string.ascii_uppercase, k=4))
    last_two = ''.join(random.choices(string.digits, k=2))
    code = first_two + next_four + last_two
    return code

def check_database():
    db_path = os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    if not os.path.isfile(db_path):
        create_database()

check_database()

def get_db_connection():
    db_path = os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

@ImproperAccessControl.route('/')
def home():
    return render_template('index.html')

@ImproperAccessControl.route('/index.html')
def index_html():
    return render_template('index.html', user=session.get('user'))

@ImproperAccessControl.route('/login.html')
def login_html():
    return render_template('login.html')

@ImproperAccessControl.route('/join.html')
def join_html():
    return render_template('join.html')

@ImproperAccessControl.route('/forgot-password.html')
def forgor_password_html():
    return render_template('forgot-password.html')

@ImproperAccessControl.route('/acceptable.html')
def acceptable_html():
    return render_template('acceptable.html', user=session.get('user'))

@ImproperAccessControl.route('/check.html')
def check_html():
    return render_template('check.html')

@ImproperAccessControl.route('/term.html')
def term_html():
    return render_template('term.html', user=session.get('user'))

@ImproperAccessControl.route('/privacy.html')
def privacy_html():
    return render_template('privacy.html', user=session.get('user'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:  
            return redirect(url_for('login_html', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@ImproperAccessControl.route('/confirm', methods=['POST'])
def confirm():
    username = request.form.get('username')
    password = request.form.get('password')
    code = request.form.get('confirmationcode')
    hash_password=hashlib.md5(password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT *FROM users WHERE username = ? or gmail = ? AND password=? AND code = ?", (username, username, hash_password, code))
    user = cursor.fetchone()
    
    if user:
        cursor.execute("UPDATE users SET active = 1 WHERE username = ? or gmail = ?", (username, username))
        conn.commit()
        conn.close()
        session['user'] = username
        return redirect(url_for('dashboard'))
    
    conn.close()
    error_message = "Invalid code"
    return render_template('confirm.html', error=error_message, username=username, password=password)

@ImproperAccessControl.route('/check', methods=['POST'])
def check():
    username = request.form.get('username')
    sessioncode = request.form.get('sessioncode')
    if username in flag_data:
        if flag_data[username] == sessioncode:
            if username in req_res_data:
                if req_res_data[username] == 2:
                    return render_template('success.html', user=username)
                else:
                    return render_template('check.html', error="username and sessioncode is currect but you don't exploit vulnerability")
            else:
                return render_template('check.html', error="please exploit vulnerability")
        else:
            return render_template('check.html', error="wrong session code")
    else:
        return render_template('check.html', error="user not found")


@ImproperAccessControl.route('/resend', methods=['POST'])
def resend():
    username = request.form.get('username')
    password = request.form.get('password')
    hash_password=hashlib.md5(password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT code FROM users WHERE username = ? or gmail = ? AND password = ?", (username, username, hash_password))
    code = cursor.fetchone()
    if code:
        username=username
        username = username.replace(" ", "")
        bdcontent = "<h2>Verify Your Account password</h2><p>your verification code are given below</p><div style=\"background-color: orange; color: black; font-size: 14px; padding: 10px; border-radius: 5px; font-family: Arial, sans-serif;\">"+code[0]+"</div><p>If you did not request this, please ignore this email.</p>"
        mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
        payload = {"email": username,
                    "sender":"IHA089 Labs ::: ImproperAccessControlLab",
                    "subject":"ImproperAccessControlLab::Verify Your Accout",
                    "bodycontent":bdcontent
                }
        try:
            k = requests.post(mail_server, json = payload)
        except:
            return jsonify({"error": "Mail server is not responding"}), 500
        error_message="code sent"
    else:
        error_message="Invalid username or password"

    conn.close()
    return render_template('confirm.html', error=error_message, username=username, password=password)
    
@ImproperAccessControl.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()
    hash_password = hashlib.md5(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE username = ? or gmail = ? AND password = ?", (username, username, hash_password))
    user = cursor.fetchone()
    conn.close()

    if user:
        if not user[4] == 1:
            return render_template('confirm.html', username=username, password=password)
        session['user'] = username
        return redirect(url_for('dashboard'))
    error_message = "Invalid username or password. Please try again."
    return render_template('login.html', error=error_message)

@ImproperAccessControl.route('/resetpassword', methods=['POST'])
def resetpassword():
    password=request.form.get('password')
    token = request.form.get('token')
    if not token or token == "11111111111111111111":
        flash("Token is missing.")
        return redirect(url_for('home'))
    query = "SELECT gmail FROM token_info where token = ?"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, (token,))
    result = cursor.fetchone()
    conn.close()
    if result:
        gmail = result[0]
        req_res_data[gmail] = req_res_data[gmail]+1
        conn = get_db_connection()
        cursor = conn.cursor()
        hash_password = hashlib.md5(password.encode()).hexdigest()
        query = "UPDATE users SET password = ? WHERE gmail = ?"
        cursor.execute(query, (hash_password, result[0], ))
        conn.commit()
        conn.close()
        flash("Password updated successfully.")
        conn = get_db_connection()
        cursor = conn.cursor()
        query = "UPDATE token_info SET token = 11111111111111111111 WHERE gmail = ?"
        cursor.execute(query, (result[0], ))
        conn.commit()
        conn.close()
        return redirect(url_for('login_html'))
    else:
        flash("Invalid token. Please try again.")
        return redirect(url_for('home'))

@ImproperAccessControl.route('/join', methods=['POST'])
def join():
    email = request.form.get('email')
    username = request.form.get('username')
    password = request.form.get('password')
    if not email.endswith('@iha089.org'):
        error_message = "Only email with @iha089.org domain is allowed."
        return render_template('join.html', error=error_message)
    conn = get_db_connection()
    cursor = conn.cursor()
    hash_password = hashlib.md5(password.encode()).hexdigest()
    
    cursor.execute("SELECT * FROM users where gmail = ?", (email,))
    if cursor.fetchone():
        error_message = "Email already taken. Please choose another."
        conn.close()
        return render_template('join.html', error=error_message)
    else:
        try:
            code = generate_code()
            query = f"INSERT INTO users (gmail, username, password, active, code) VALUES ('{email}', '{username}', '{hash_password}', '0', '{code}')".format(email, username, hash_password, code)
            cursor.execute(query)
            conn.commit()
            username=email
            username = username.replace(" ", "")
            bdcontent = "<h2>Verify Your Account password</h2><p>your verification code are given below</p><div style=\"background-color: orange; color: black; font-size: 14px; padding: 10px; border-radius: 5px; font-family: Arial, sans-serif;\">"+code+"</div><p>If you did not request this, please ignore this email.</p>"
            mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
            payload = {"email": username,
                        "sender":"IHA089 Labs ::: ImproperAccessControlLab",
                        "subject":"ImproperAccessControlLab::Verify Your Accout",
                        "bodycontent":bdcontent
                    }
            try:
                k = requests.post(mail_server, json = payload)
            except:
                return jsonify({"error": "Mail server is not responding"}), 500

            return render_template('confirm.html', username=email, password=password)
        except sqlite3.Error as err:
            error_message = "Something went wrong, Please try again later."
            return render_template('join.html', error=error_message)
        conn.close()
    
@ImproperAccessControl.route('/reset', methods=['GET'])
def reset():
    token = request.args.get('token')
    if not token:
        flash("Token is missing.")
        return redirect(url_for('home'))
    query = "SELECT gmail FROM token_info where token = ?"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, (token,))
    result = cursor.fetchone()
    conn.close()
    if result:
        mail = result[0]
        req_res_data[mail] = req_res_data[mail]+1
        return render_template('reset-password.html', token=token)
    else:
        flash("Invalid token. Please try again.")
        return redirect(url_for('home'))


@ImproperAccessControl.route('/forgot', methods=['POST'])
def forgot():
    try:
        data = request.get_json()
        if 'username' in data:
            uname = data['username']

            conn = get_db_connection()
            cursor = conn.cursor()
            query = "SELECT 1 FROM users WHERE gmail = ?"
            cursor.execute(query, (uname,))
            result = cursor.fetchone()
            conn.close()
            if result is not None:
                token = secrets.token_hex(32)
                conn = get_db_connection()
                cursor = conn.cursor()
                query = "SELECT 1 FROM token_info WHERE gmail = ?"
                cursor.execute(query, (uname, ))
                result = cursor.fetchone()
                
                if result is not None:
                    current_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
                    query = "UPDATE token_info SET token = ?, timestamp = ? WHERE gmail = ?"
                    cursor.execute(query, (token, current_timestamp, uname, ))
                    conn.commit()
                else:
                    query = f"INSERT INTO token_info(gmail, token) VALUES ('{uname}', '{token}')".format(uname, token)
                    cursor.execute(query)
                    conn.commit()
                conn.close()
                username = data['username']
                username = username.replace(" ", "")
                req_url = request.url.replace("/forgot","")
                cmplt_url = req_url+"/reset?token="+token
                if "iha089-labs.in" not in req_url:
                    req_res_data[username]=0
                bdcontent = "<h2>Reset Your Account password</h2><p>Click the button below to reset your account password on Improper Access Control Lab</p><a href=\""+cmplt_url+"\">Verify Your Account</a><p>If you did not request this, please ignore this email.</p>"
                mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
                payload = {"email": username,
                            "sender":"IHA089 Labs ::: ImproperAccessControlLab",
                            "subject":"ImproperAccessControlLab::Click bellow link to reset your password",
                            "bodycontent":bdcontent
                    }
                k = requests.post(mail_server, json = payload)
            else:
                pass

            return jsonify({"message": "Reset link sent on your mail"}), 200
        else:
            return jsonify({"error": "Username is required"}), 400
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
 

@ImproperAccessControl.route('/dashboard')
@ImproperAccessControl.route("/dashboard.html")
@login_required
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login_html'))
    
    username = session.get('user')
    if username not in flag_data:
        flag_data[username] = generate_flag()

    flag_code = flag_data[username]

    return render_template('dashboard.html', user=session.get('user'), flag=flag_code)

@ImproperAccessControl.route('/logout.html')
def logout():
    session.clear() 
    return redirect(url_for('login_html'))

@ImproperAccessControl.route('/profile')
@ImproperAccessControl.route('/profile.html')
@login_required
def profile():
    if 'user' not in session:
        return redirect(url_for('login_html'))

    return render_template('profile.html', user=session.get('user'))


@ImproperAccessControl.route('/reset_password', methods=['POST'])
def reset_password():
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    token = request.form.get('token')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    expected_token = hashlib.md5(f"{user['id']}2024".encode()).hexdigest()
    if token == expected_token:
        hash_password = hashlib.md5(new_password.encode()).hexdigest()
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hash_password, user['id']))
        conn.commit()
        conn.close()
        return jsonify({"message": "Password updated successfully!"})
    
    conn.close()
    return jsonify({"error": "Invalid token"}), 400

@ImproperAccessControl.after_request
def add_cache_control_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

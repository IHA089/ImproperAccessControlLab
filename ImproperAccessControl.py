from flask import Flask, request, render_template, session, jsonify, redirect, url_for, flash
from functools import wraps
from datetime import datetime
import sqlite3, hashlib, requests, secrets, logging, os, random

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

lab_type = "AccountTakeover"
lab_name = "ImproperAccessControlLab"

ImproperAccessControl = Flask(__name__)
ImproperAccessControl.secret_key = "vulnerable_lab_by_IHA089"

def create_database():
    db_path = os.path.join(os.getcwd(), lab_type, lab_name, 'users.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        gmail TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    ''')

    numb = random.randint(100, 999)
    passw = "admin@"+str(numb)
    passw_hash = hashlib.md5(passw.encode()).hexdigest()
    query = "INSERT INTO users (gmail, username, password) VALUES ('admin@iha089.org', 'admin', '"+passw_hash+"')"
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
            query = f"INSERT INTO users (gmail, username, password) VALUES ('{email}', '{username}', '{hash_password}')".format(email, username, hash_password)
            cursor.execute(query)
            conn.commit()
            return render_template('login.html')
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
                bdcontent = "<h2>Reset Your Account password</h2><p>Click the button below to reset your account password on Improper Access Control Lab</p><a href=\""+cmplt_url+"\">Verify Your Account</a><p>If you did not request this, please ignore this email.</p>"
                mail_server = "https://127.0.0.1:7089/dcb8df93f8885473ad69681e82c423163edca1b13cf2f4c39c1956b4d32b4275"
                payload = {"email": username,
                            "sender":"IHA089 Labs",
                            "subject":"Click bellow link to reset your password",
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
    print(session['user'])
    if 'user' not in session:
        return redirect(url_for('login_html'))
    admin_list=['admin', 'administrator', 'admin@iha089.org']
    if session.get('user') in admin_list:
        return render_template('admin-dashboard.html', user=session.get('user'))

    return render_template('dashboard.html', user=session.get('user'))

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

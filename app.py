from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
# from sendgrid import SendGridAPIClient
# from sendgrid.helpers.mail import Mail
from dotenv import load_dotenv
import sqlite3
import os
import time
import random

# ---------------- Load environment variables ----------------
load_dotenv()
# SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
# FROM_EMAIL = os.getenv("FROM_EMAIL")

# ---------------- Flask setup ----------------
app = Flask(__name__)
app.secret_key = "supersecretkey"

# ---------------- Database setup ----------------
DB_DIR = os.path.join(app.root_path, "instance")
DB_PATH = os.path.join(DB_DIR, "database.db")
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            otp TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ---------------- OTP Helpers ----------------
OTP_TTL_SECONDS = 5*60
MAX_RESEND_ATTEMPTS = 3

def send_otp_email(to_email, otp_code, username_display=None):
    """
    SendGrid OTP sending function.
    Currently commented to avoid 401 Unauthorized errors on Render.
    Uncomment and set environment variables to use.
    """
    # body_html = f"<h3>Hello {username_display},</h3><p>Your OTP is <b>{otp_code}</b>.</p>" if username_display else f"<p>Your OTP is <b>{otp_code}</b>.</p>"
    # message = Mail(
    #     from_email=FROM_EMAIL,
    #     to_emails=to_email,
    #     subject="Your OTP Verification",
    #     html_content=body_html
    # )
    # sg = SendGridAPIClient(SENDGRID_API_KEY)
    # sg.send(message)
    print(f"[DEBUG] OTP for {to_email} is {otp_code}")  # Console debug

def form_get_multi(form, *names, default=""):
    """Helper to get first available field from form."""
    for n in names:
        if n in form:
            return form.get(n, "").strip()
    return default

# ---------------- ROUTES ----------------
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/signup', methods=['POST'])
def signup():
    username = form_get_multi(request.form, 'username', 'txt')
    email = form_get_multi(request.form, 'email', 'email').lower()
    password = form_get_multi(request.form, 'password', 'pswd')

    if not username or not email or not password:
        flash("Please fill all fields.", "danger")
        return redirect(url_for('index'))

    hashed_pw = generate_password_hash(password)
    conn = get_db()
    c = conn.cursor()
    try:
        otp = str(random.randint(100000, 999999))
        c.execute("INSERT INTO users (username,email,password,otp) VALUES (?,?,?,?)", (username,email,hashed_pw,otp))
        conn.commit()
        conn.close()

        session['pending_email'] = email
        session['otp_time'] = time.time()
        session['resend_count'] = 0

        # Optional OTP email
        # send_otp_email(email, otp, username_display=username)

        flash("Signup successful — OTP sent.", "info")
        return redirect(url_for('verify'))

    except sqlite3.IntegrityError:
        conn.close()
        flash("Email already exists.", "warning")
        return redirect(url_for('index'))

@app.route('/verify', methods=['GET','POST'])
def verify():
    pending_email = session.get('pending_email') or request.args.get('email')
    if request.method=='POST':
        otp_entered = form_get_multi(request.form,'otp')
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT otp,verified,username FROM users WHERE email=?",(pending_email,))
        row = c.fetchone()
        if not row:
            conn.close()
            flash("Account not found.", "danger")
            return redirect(url_for('index'))

        if row['verified']==1:
            conn.close()
            flash("Account already verified.", "info")
            return redirect(url_for('index'))

        if otp_entered==row['otp']:
            c.execute("UPDATE users SET verified=1, otp=NULL WHERE email=?",(pending_email,))
            conn.commit()
            conn.close()
            session.pop('pending_email',None)
            session.pop('otp_time',None)
            session.pop('resend_count',None)
            flash("✅ Email verified! Redirecting...", "success")
            return render_template("otp.html", redirect_to="dashboard")
        else:
            conn.close()
            flash("Invalid OTP.", "danger")
            return redirect(url_for('verify'))

    return render_template("verify.html", pending_email=pending_email, remaining="05:00")

@app.route('/login', methods=['POST'])
def login():
    email = form_get_multi(request.form,'email').lower()
    password = form_get_multi(request.form,'password','pswd')
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=?",(email,))
    user = c.fetchone()
    conn.close()
    if not user:
        flash("No account with that email.", "danger")
        return redirect(url_for('index'))

    if user['verified']==0:
        otp = str(random.randint(100000,999999))
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE users SET otp=? WHERE email=?",(otp,email))
        conn.commit()
        conn.close()
        session['pending_email']=email
        session['otp_time']=time.time()
        flash("Account not verified. OTP sent.", "warning")
        # send_otp_email(email, otp, username_display=user['username'])
        return redirect(url_for('verify'))

    if check_password_hash(user['password'],password):
        session['user_id']=user['id']
        session['user']=user['username']
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for('dashboard'))
    else:
        flash("Incorrect password.", "danger")
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please login first.", "warning")
        return redirect(url_for('index'))
    return render_template("welcome.html", username=session.get('user'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('index'))

if __name__=="__main__":
    app.run(debug=True)

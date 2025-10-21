from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ---------------- Database setup ----------------
DB_DIR = app.instance_path
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "database.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
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

# ---------------- ROUTES ----------------
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '').strip()

    if not username or not email or not password:
        flash("Please fill all fields.", "danger")
        return redirect(url_for('index'))

    hashed_pw = generate_password_hash(password)
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                  (username, email, hashed_pw))
        conn.commit()
        flash("Signup successful. You can now login.", "success")
    except sqlite3.IntegrityError:
        flash("Email already exists.", "warning")
    finally:
        conn.close()
    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '').strip()

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=?", (email,))
    user = c.fetchone()
    conn.close()

    if not user:
        flash("No account with that email.", "danger")
        return redirect(url_for('index'))

    if check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['user'] = user['username']
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

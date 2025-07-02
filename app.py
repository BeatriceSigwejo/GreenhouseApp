import os
from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import sqlite3
import io
from datetime import datetime, timedelta
import pandas as pd
import re
import secrets
import string
import random
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_fallback')

# Flask-Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.zoho.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# --- Database Initialization ---
def init_db():
    db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
    with sqlite3.connect(db_path, timeout=10) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS sensor_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sensors INTEGER,
            temp REAL,
            ldr INTEGER,
            moisture TEXT,
            pump TEXT,
            heater TEXT,
            fan TEXT,
            light TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            download_time TEXT NOT NULL,
            start_date TEXT,
            end_date TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            username TEXT NOT NULL
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details TEXT
        )''')
        conn.commit()

# Initialize the database
init_db()

# Helper function to log actions
def log_action(username, action, details=None):
    db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO system_logs (username, action, timestamp, details)
                        VALUES (?, ?, ?, ?)''',
                      (username, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), details))
            conn.commit()
    except sqlite3.OperationalError as e:
        print(f"Database error in log_action: {e}")

# --- Routes ---
@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/receive', methods=['GET'])
def receive():
    user = request.args.get('user')
    passwd = request.args.get('pass')
    if user != 'matumiziDaily' or passwd != 'matumiziDaily':
        return "Unauthorized", 403
    try:
        sensors = int(request.args.get('sensors', 1))
        temp = float(request.args.get('temp', 0))
        ldr = int(request.args.get('ldr', 0))
        moisture = request.args.get('moisture', 'N/A')
        pump = request.args.get('pump', 'OFF')
        heater = request.args.get('heater', 'OFF')
        fan = request.args.get('fan', 'OFF')
        light = request.args.get('light', 'OFF')
        db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
        with sqlite3.connect(db_path, timeout=10) as conn:
            c = conn.cursor()
            c.execute('''INSERT INTO sensor_data (timestamp, sensors, temp, ldr, moisture, pump, heater, fan, light)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), sensors, temp, ldr, moisture, pump, heater, fan, light))
            conn.commit()
        return "Data saved successfully"
    except Exception as e:
        print(f"Error saving data: {e}")
        return str(e), 400

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Initialize filter parameters
            start_date = request.form.get('start_date') if request.method == 'POST' else None
            end_date = request.form.get('end_date') if request.method == 'POST' else None
            query = "SELECT * FROM sensor_data"
            params = []
            
            # Apply filters if provided
            if start_date and end_date:
                query += " WHERE timestamp BETWEEN ? AND ?"
                params = [start_date, end_date + " 23:59:59"]
            
            # Fetch filtered data (limit to 10 for display)
            c.execute(query + " ORDER BY id DESC LIMIT 10", params)
            data = c.fetchall()
            
            # Fetch latest row
            c.execute("SELECT * FROM sensor_data ORDER BY id DESC LIMIT 1")
            latest_row = c.fetchone()
            
            # Fetch data for graph
            c.execute("SELECT timestamp, temp FROM sensor_data ORDER BY id DESC LIMIT 20")
            graph_rows = c.fetchall()
            
        latest = latest_row if latest_row else {'sensors': 0, 'temp': 'N/A', 'ldr': 'N/A', 'moisture': 'N/A'}
        graph_timestamps = [row['timestamp'] for row in reversed(graph_rows)]
        graph_temps = [row['temp'] for row in reversed(graph_rows)]
        
        return render_template('dashboard.html',
                              data=data,
                              latest=latest,
                              logged_in='user' in session,
                              graph_timestamps=graph_timestamps,
                              graph_temps=graph_temps,
                              start_date=start_date,
                              end_date=end_date)
    except sqlite3.OperationalError as e:
        print(f"Database error in dashboard: {e}")
        return render_template('dashboard.html', error="Database is temporarily unavailable. Please try again.")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
        try:
            with sqlite3.connect(db_path, timeout=10) as conn:
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username=? AND password=? AND verified=1", (username, password))
                user = c.fetchone()
                if user:
                    session['user'] = username
                    session['is_admin'] = user[5]
                    log_action(username, "Login", "User logged in successfully")
                    if user[5]:
                        return redirect(url_for('admin_dashboard'))
                    return redirect(url_for('dashboard'))
                c.execute("SELECT * FROM users WHERE username=? AND password=? AND verified=0", (username, password))
                unverified_user = c.fetchone()
                if unverified_user:
                    log_action(username, "Login Failed", "Email not verified")
                    return render_template('login.html', error='❌ Your email is not verified. Please check your inbox.')
                log_action(username, "Login Failed", "Invalid credentials")
                return render_template('login.html', error='❌ Invalid credentials. Please try again.')
        except sqlite3.OperationalError as e:
            print(f"Database error in login: {e}")
            return render_template('login.html', error='❌ Database is temporarily unavailable. Please try again.')
    return render_template('login.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
        try:
            with sqlite3.connect(db_path, timeout=10) as conn:
                c = conn.cursor()
                c.execute("SELECT username FROM users WHERE email=?", (email,))
                user = c.fetchone()
                if user:
                    token = s.dumps(email, salt='password-reset')
                    expires_at = (datetime.now() + timedelta(hours=1)).isoformat()

                    try:
                        c.execute("INSERT INTO password_resets (email, token, expires_at, username) VALUES (?, ?, ?, ?)",
                                  (email, token, expires_at, user[0]))
                        conn.commit()
                    except sqlite3.OperationalError as e:
                        print(f"[DB ERROR] {e}")
                        return render_template('forgot.html', error="Database error occurred.")
                    
                    reset_link = url_for('reset_password', token=token, _external=True)
                    msg = Message("Password Reset Request",
                                  recipients=[email],
                                  body=f"""Click the following link to reset your password: {reset_link}

This link will expire in 1 hour.""",
                                  sender=app.config['MAIL_USERNAME'])
                    try:
                        mail.send(msg)
                        return render_template('forgot.html', message="Password reset link sent to your email")
                    except Exception as e:
                        print(f"[EMAIL ERROR] {type(e).__name__}: {str(e)}")
                        return render_template('forgot.html', error=f"Failed to send reset link. Error: {type(e).__name__}")
                return render_template('forgot.html', error="Email not found")
        except sqlite3.OperationalError as e:
            print(f"Database error in forgot_password: {e}")
            return render_template('forgot.html', error="Database is temporarily unavailable. Please try again.")
    return render_template('forgot.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            c = conn.cursor()
            c.execute("SELECT email, expires_at FROM password_resets WHERE token=?", (token,))
            reset_record = c.fetchone()
            
            if not reset_record:
                return render_template('forgot.html', error="❌ Reset link is invalid or has expired.")
            
            email, expires_at = reset_record
            expires_at_dt = datetime.fromisoformat(expires_at)
            if datetime.now() > expires_at_dt:
                return render_template('forgot.html', error="❌ Reset link has expired.")
            
            try:
                confirmed_email = s.loads(token, salt='password-reset', max_age=3600)
                if confirmed_email != email:
                    return render_template('forgot.html', error="❌ Invalid reset link.")
                
                if request.method == 'POST':
                    new_password = request.form['password']
                    c.execute("UPDATE users SET password=? WHERE email=?", (new_password, email))
                    c.execute("DELETE FROM password_resets WHERE token=?", (token,))
                    conn.commit()
                    return render_template('login.html', message="✅ Password reset successfully. Please log in.")
                
                return render_template('reset.html', token=token)
            except Exception as e:
                return render_template('forgot.html', error="❌ Reset link is invalid or has expired.")
    except sqlite3.OperationalError as e:
        print(f"Database error in reset_password: {e}")
        return render_template('forgot.html', error="Database is temporarily unavailable. Please try again.")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            log_action(username, "Registration Failed", "Passwords do not match")
            return render_template('register.html', error="❌ Passwords do not match.")
        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password):
            suggested = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            log_action(username, "Registration Failed", "Password does not meet requirements")
            return render_template(
                'register.html',
                error='❌ Password must be at least 8 characters and include uppercase, lowercase, and numbers.',
                suggestion=suggested
            )
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            log_action(username, "Registration Failed", "Invalid email format")
            return render_template('register.html', error="❌ Invalid email format.")
        db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
        try:
            with sqlite3.connect(db_path, timeout=10) as conn:
                c = conn.cursor()
                c.execute("SELECT * FROM users WHERE username=?", (username,))
                if c.fetchone():
                    log_action(username, "Registration Failed", "Username already exists")
                    return render_template('register.html', error="❌ Username already exists.")
                c.execute("INSERT INTO users (username, email, password, verified, is_admin) VALUES (?, ?, ?, ?, ?)",
                          (username, email, password, 0, 0))
                conn.commit()
            token = s.dumps(email, salt='email-confirm')
            verify_url = url_for('verify_email', token=token, _external=True)
            try:
                msg = Message("Verify your Email - Greenhouse System",
                              sender=app.config['MAIL_USERNAME'],
                              recipients=[email])
                msg.body = f"""Hi,

Thank you for registering with the Greenhouse System.

Please click the link below to verify your email address:
{verify_url}

If you did not register, you can ignore this email.
"""
                mail.send(msg)
                log_action(username, "Registration", f"User registered with email: {email}")
                return render_template('register.html', error="✅ Registration successful. Please check your inbox to verify your email.")
            except Exception as e:
                log_action(username, "Registration Failed", f"Failed to send email: {str(e)}")
                return render_template('register.html', error=f"❌ Failed to send email. {str(e)}")
        except sqlite3.OperationalError as e:
            print(f"Database error in register: {e}")
            log_action(username, "Registration Failed", f"Database error: {str(e)}")
            return render_template('register.html', error="Database is temporarily unavailable. Please try again.")
    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
        try:
            with sqlite3.connect(db_path, timeout=10) as conn:
                c = conn.cursor()
                c.execute("SELECT username, is_admin FROM users WHERE email=?", (email,))
                user = c.fetchone()
                if user:
                    c.execute("UPDATE users SET verified=1 WHERE email=?", (email,))
                    conn.commit()
                    session['user'] = user[0]
                    session['is_admin'] = user[1]
                    log_action(user[0], "Email Verification", "Email verified successfully")
                    return redirect(url_for('dashboard'))
                log_action("Unknown", "Email Verification Failed", f"User not found for email: {email}")
                return render_template('register.html', error="❌ User not found.")
        except sqlite3.OperationalError as e:
            print(f"Database error in verify_email: {e}")
            log_action("Unknown", "Email Verification Failed", f"Database error: {str(e)}")
            return render_template('register.html', error="Database is temporarily unavailable. Please try again.")
    except Exception as e:
        log_action("Unknown", "Email Verification Failed", f"Verification link invalid or expired: {str(e)}")
        return render_template('register.html', error="❌ Verification link is invalid or has expired.")

@app.route('/logout')
def logout():
    username = session.get('user', 'Unknown')
    session.pop('user', None)
    session.pop('is_admin', None)
    log_action(username, "Logout", "User logged out")
    return redirect(url_for('login'))

@app.route('/download', methods=['POST'])
def download():
    if 'user' not in session:
        return redirect(url_for('login'))
    db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            c = conn.cursor()
            query = "SELECT * FROM sensor_data"
            params = []
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')
            details = "Downloaded all data"
            if start_date and end_date:
                query += " WHERE timestamp BETWEEN ? AND ?"
                params = [start_date, end_date + " 23:59:59"]
                details = f"Downloaded data from {start_date} to {end_date}"
            df = pd.read_sql_query(query, conn, params=params)
            c.execute("INSERT INTO downloads (username, download_time, start_date, end_date) VALUES (?, ?, ?, ?)",
                      (session['user'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), start_date, end_date))
            log_action(session['user'], "Download", details)
            conn.commit()
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Greenhouse_Data')
        output.seek(0)
        filename = f"greenhouse_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(output, download_name=filename, as_attachment=True,
                        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    except sqlite3.OperationalError as e:
        print(f"Database error in download: {e}")
        return render_template('dashboard.html', error="Database is temporarily unavailable. Please try again.")

@app.route('/admin')
def admin_dashboard():
    if 'user' not in session or not session.get('is_admin'):
        return "Unauthorized: Admins only", 403
    db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT username, email, verified, is_admin FROM users")
            users = c.fetchall()
            c.execute("SELECT username, download_time, start_date, end_date FROM downloads ORDER BY download_time DESC")
            downloads = c.fetchall()
        return render_template('admin.html', users=users, downloads=downloads)
    except sqlite3.OperationalError as e:
        print(f"Database error in admin_dashboard: {e}")
        return render_template('admin.html', error="Database is temporarily unavailable. Please try again.")

@app.route('/admin/delete_user/<username>', methods=['POST'])
def delete_user(username):
    if 'user' not in session or not session.get('is_admin'):
        return "Unauthorized: Admins only", 403
    if username == session['user']:
        return "Cannot delete your own account", 403
    db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE username=?", (username,))
            log_action(session['user'], "Delete User", f"Deleted user: {username}")
            conn.commit()
        return redirect(url_for('admin_dashboard'))
    except sqlite3.OperationalError as e:
        print(f"Database error in delete_user: {e}")
        return render_template('admin.html', error="Database is temporarily unavailable. Please try again.")

@app.route('/admin/toggle_admin/<username>', methods=['POST'])
def toggle_admin(username):
    if 'user' not in session or not session.get('is_admin'):
        return "Unauthorized: Admins only", 403
    if username == session['user']:
        return "Cannot change your own admin status", 403
    db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            c = conn.cursor()
            c.execute("SELECT is_admin FROM users WHERE username=?", (username,))
            user = c.fetchone()
            if user:
                new_status = 0 if user[0] == 1 else 1
                c.execute("UPDATE users SET is_admin=? WHERE username=?", (new_status, username))
                log_action(session['user'], "Toggle Admin Status", f"Changed admin status for {username} to {'Admin' if new_status else 'Non-Admin'}")
                conn.commit()
        return redirect(url_for('admin_dashboard'))
    except sqlite3.OperationalError as e:
        print(f"Database error in toggle_admin: {e}")
        return render_template('admin.html', error="Database is temporarily unavailable. Please try again.")

@app.route('/admin/system_logs', methods=['GET', 'POST'])
def system_logs():
    if 'user' not in session or not session.get('is_admin'):
        return "Unauthorized: Admins only", 403
    db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            query = "SELECT username, action, timestamp, details FROM system_logs"
            params = []
            
            # Apply filters if provided
            if request.method == 'POST':
                username = request.form.get('username')
                action = request.form.get('action')
                conditions = []
                if username:
                    conditions.append("username LIKE ?")
                    params.append(f"%{username}%")
                if action:
                    conditions.append("action = ?")
                    params.append(action)
                if conditions:
                    query += " WHERE " + " AND ".join(conditions) 
            
            query += " ORDER BY timestamp DESC LIMIT 50"
            c.execute(query, params)
            logs = c.fetchall()
        return render_template('system_logs.html', logs=logs)
    except sqlite3.OperationalError as e:
        print(f"Database error in system_logs: {e}")
        return render_template('system_logs.html', logs=[], error="Database is temporarily unavailable. Please try again.")

@app.route('/create_admin')
def create_admin():
    db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password, verified, is_admin) VALUES (?, ?, ?, ?, ?)",
                      ('admin', 'admin@example.com', 'Admin123', 1, 1))
            log_action('System', "Create Admin", "Created admin user: admin")
            conn.commit()
        return "Admin user created"
    except sqlite3.IntegrityError:
        return "Admin user already exists"
    except sqlite3.OperationalError as e:
        print(f"Database error in create_admin: {e}")
        return "Database is temporarily unavailable. Please try again."
    finally:
        pass

@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if not session.get('is_admin'):
        return redirect(url_for('dashboard'))
    db_path = os.path.join(os.path.dirname(__file__), 'greenhouse.db')
    try:
        with sqlite3.connect(db_path, timeout=10) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT username, email, verified, is_admin FROM users")
            users = c.fetchall()
            
            if request.method == 'POST':
                action = request.form.get('action')
                if action == 'add_user':
                    username = request.form.get('username')
                    email = request.form.get('email')
                    password = request.form.get('password')
                    is_admin = int(request.form.get('is_admin', 0))
                    if not username or not email or not password:
                        return render_template('settings.html', users=users, error="All fields are required")
                    try:
                        c.execute("INSERT INTO users (username, email, password, verified, is_admin) VALUES (?, ?, ?, ?, ?)",
                                  (username, email, password, 1, is_admin))
                        log_action(session['user'], "Add User", f"Added user: {username}, Admin: {'Yes' if is_admin else 'No'}")
                        conn.commit()
                        return render_template('settings.html', users=users, message="User added successfully")
                    except sqlite3.IntegrityError:
                        return render_template('settings.html', users=users, error="Username or email already exists")
                elif action == 'delete':
                    username = request.form.get('username')
                    if not username:
                        return render_template('settings.html', users=users, error="No user selected")
                    if username == session['user']:
                        return render_template('settings.html', users=users, error="Cannot delete your own account")
                    c.execute("DELETE FROM users WHERE username=?", (username,))
                    log_action(session['user'], "Delete User", f"Deleted user: {username}")
                    conn.commit()
                    c.execute("SELECT username, email, verified, is_admin FROM users")
                    users = c.fetchall()
                    return render_template('settings.html', users=users, message="User deleted successfully")
                elif action == 'toggle_admin':
                    username = request.form.get('username')
                    if not username:
                        return render_template('settings.html', users=users, error="No user selected")
                    if username == session['user']:
                        return render_template('settings.html', users=users, error="Cannot change your own admin status")
                    c.execute("SELECT is_admin FROM users WHERE username=?", (username,))
                    user = c.fetchone()
                    if user:
                        new_status = 0 if user['is_admin'] else 1
                        c.execute("UPDATE users SET is_admin=? WHERE username=?", (new_status, username))
                        log_action(session['user'], "Toggle Admin Status", f"Changed admin status for {username} to {'Admin' if new_status else 'Non-Admin'}")
                        conn.commit()
                    c.execute("SELECT username, email, verified, is_admin FROM users")
                    users = c.fetchall()
                    return render_template('settings.html', users=users, message=f"Admin status for {username} updated")
        return render_template('settings.html', users=users)
    except sqlite3.OperationalError as e:
        print(f"Database error in admin_settings: {e}")
        return render_template('settings.html', users=[], error="Database is temporarily unavailable. Please try again.")

@app.route('/manage_user', methods=['POST'])
def manage_user():
    if not session.get('is_admin'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('admin_settings'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
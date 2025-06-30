from flask import Flask, render_template, request, redirect, url_for, session
from flask_mail import Mail, Message                      
from itsdangerous import URLSafeTimedSerializer           
import sqlite3
import io
from datetime import datetime
import pandas as pd
import re                                                
import secrets                                            
import string
import os
import smtplib
from email.mime.text import MIMEText                

app = Flask(__name__)
app.secret_key = 'your_secret_key' # For production, use a more secure, randomly generated key

# Flask-Mail configuration (add this block)
app.config['MAIL_SERVER'] = 'smtp.zoho.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'greenhousetz@fierylion.live'        # <-- your Gmail
app.config['MAIL_PASSWORD'] = 'BhPp4aAneQYM'     # <-- your App password

mail = Mail(app)                                           # Initialize Flask-Mail
s = URLSafeTimedSerializer(app.secret_key)                 # Token serializer for email verification

# --- Database Initialization ---
def init_db():
    conn = sqlite3.connect('greenhouse.db')
    c = conn.cursor()
    # Create users table with a UNIQUE constraint on username
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        verified INTEGER DEFAULT 0
    )''')
    # Create sensor data table
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
    conn.commit()
    conn.close()

# Initialize the database when the app starts
init_db()

# --- Routes ---
@app.route('/')
def index():
    # If user is logged in, go to dashboard, otherwise go to login
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/receive', methods=['GET'])
def receive():
    # This endpoint is for receiving data from your hardware
    user = request.args.get('user')
    passwd = request.args.get('pass')
    # Simple authentication for the hardware endpoint
    if user != 'matumiziDaily' or passwd != 'matumiziDaily':
        return "Unauthorized", 403

    try:
        # Safely get data from request arguments
        sensors = int(request.args.get('sensors', 1))
        temp = float(request.args.get('temp', 0))
        ldr = int(request.args.get('ldr', 0))
        moisture = request.args.get('moisture', 'N/A')
        pump = request.args.get('pump', 'OFF')
        heater = request.args.get('heater', 'OFF')
        fan = request.args.get('fan', 'OFF')
        light = request.args.get('light', 'OFF')

        conn = sqlite3.connect('greenhouse.db')
        c = conn.cursor()
        c.execute('''INSERT INTO sensor_data (timestamp, sensors, temp, ldr, moisture, pump, heater, fan, light)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), sensors, temp, ldr, moisture, pump, heater, fan, light))
        conn.commit()
        conn.close()

        return "Data saved successfully"
    except Exception as e:
        # Log the error for debugging
        print(f"Error saving data: {e}")
        return str(e), 400

@app.route('/dashboard')
def dashboard():
    # Protect the dashboard route
    if 'user' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('greenhouse.db')
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    c = conn.cursor()
    
    # Data for the table (latest 10 entries)
    c.execute("SELECT * FROM sensor_data ORDER BY id DESC LIMIT 10")
    data = c.fetchall()

    # Data for the latest status cards
    c.execute("SELECT * FROM sensor_data ORDER BY id DESC LIMIT 1")
    latest_row = c.fetchone()
    
    # Data for the graph (fetch last 20 entries)
    c.execute("SELECT timestamp, temp FROM sensor_data ORDER BY id DESC LIMIT 20")
    graph_rows = c.fetchall()
    conn.close()
    
    latest = latest_row if latest_row else {'sensors': 0, 'temp': 'N/A', 'ldr': 'N/A', 'moisture': 'N/A'}
    
    # Prepare lists for the graph, reversing them for chronological order (left to right)
    graph_timestamps = [row['timestamp'] for row in reversed(graph_rows)]
    graph_temps = [row['temp'] for row in reversed(graph_rows)]

    return render_template('dashboard.html', 
                           data=data, 
                           latest=latest, 
                           logged_in='user' in session,
                           graph_timestamps=graph_timestamps,
                           graph_temps=graph_temps)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('greenhouse.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=? AND verified=1", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user'] = username
            return redirect(url_for('dashboard'))
        
        # Check if user exists but is unverified
        conn = sqlite3.connect('greenhouse.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=? AND verified=0", (username, password))
        unverified_user = c.fetchone()
        conn.close()
        if unverified_user:
            return render_template('login.html', error='❌ Your email is not verified. Please check your inbox.')
        # **MODIFIED LINE**: If login fails, re-render login page with an error message
        return render_template('login.html', error='Invalid credentials. Please try again.')
    # For GET request, just show the login page
    return render_template('login.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = sqlite3.connect('greenhouse.db')
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()
        if user:
            token = s.dumps(email, salt='password-reset')
            reset_link = url_for('reset_password', token=token, _external=True)
            send_reset_email(email, reset_link)
            return render_template('forgot.html', message="✅ A reset link has been sent to your email.")
        return render_template('forgot.html', error="❌ Email not found.")
    return render_template('forgot.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # Token valid for 1 hour
        if request.method == 'POST':
            new_password = request.form['password']
            conn = sqlite3.connect('greenhouse.db')
            c = conn.cursor()
            c.execute("UPDATE users SET password=? WHERE email=?", (new_password, email))
            conn.commit()
            conn.close()
            return render_template('login.html', message="✅ Password reset successfully. Please log in.")
        return render_template('reset.html', token=token)
    except Exception as e:
        return render_template('forgot.html', error="❌ Reset link is invalid or has expired.")

def send_reset_email(to_email, reset_link):
    try:
        msg = Message("Reset Your Password - Greenhouse System",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[to_email])
        msg.body = f"""Hi,

Click the link below to reset your password:
{reset_link}

If you did not request a password reset, you can ignore this email.
"""
        mail.send(msg)
        print(f"[EMAIL SENT] to {to_email}")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # 1. Password match check
        if password != confirm_password:
            return render_template('register.html', error="❌ Passwords do not match.")

        # 2. Password strength check
        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password):
            suggested = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
            return render_template(
                'register.html',
                error='❌ Password must be at least 8 characters and include uppercase, lowercase, and numbers.',
                suggestion=suggested
            )

        # 3. Email format validation
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, email):
            return render_template('register.html', error="❌ Invalid email format.")
        
        # 4. Check if username already exists
        conn = sqlite3.connect('greenhouse.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        if c.fetchone():
            conn.close()
            return render_template('register.html', error="❌ Username already exists.")
        
        # 5. Store user in database with unverified status
        c.execute("INSERT INTO users (username, email, password, verified) VALUES (?, ?, ?, ?)", 
          (username, email, password, 0))  # verified=0 means unverified
        conn.commit()
        conn.close()

        # 6. Generate verification token & link
        token = s.dumps(email, salt='email-confirm')
        verify_url = url_for('verify_email', token=token, _external=True)

        # 7. Send verification email
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

            return render_template('register.html', error="✅ Registration successful. Please check your inbox to verify your email.")

        except Exception as e:
            return render_template('register.html', error=f"❌ Failed to send email. {str(e)}")

    # For GET request
    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)  # token valid for 1 hour
        conn = sqlite3.connect('greenhouse.db')
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE email=?", (email,))
        user = c.fetchone()
        if user:
            # Mark user as verified
            c.execute("UPDATE users SET verified=1 WHERE email=?", (email,))
            conn.commit()
            session['user'] = user[0]  # Set session to username
            conn.close()
            return redirect(url_for('dashboard'))
        conn.close()
        return render_template('register.html', error="❌ User not found.")
    except Exception as e:
        return render_template('register.html', error="❌ Verification link is invalid or has expired.")

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/download')
def download():
    # Protect the download route
    if 'user' not in session:
        return redirect(url_for('login'))
        
    conn = sqlite3.connect('greenhouse.db')
    df = pd.read_sql_query("SELECT * FROM sensor_data", conn)
    conn.close()
    
    # Create an in-memory buffer for the Excel file
    output = io.BytesIO()
    # Use the ExcelWriter to save the dataframe to the buffer
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Greenhouse_Data')
    output.seek(0)
    
    return send_file(output, download_name='greenhouse_data.xlsx', as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

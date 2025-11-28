from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import json
import qrcode
from io import BytesIO
from PIL import Image

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a random string for production

# Initialize Database
def init_db():
    conn = sqlite3.connect('healthqr.db')
    c = conn.cursor()
    # Admin table (pre-create default admin)
    c.execute('''CREATE TABLE IF NOT EXISTS admins
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    # Hospitals table
    c.execute('''CREATE TABLE IF NOT EXISTS hospitals
                 (id INTEGER PRIMARY KEY, name TEXT, username TEXT UNIQUE, email TEXT UNIQUE, password TEXT)''')
    # Patients table (linked to hospitals)
    c.execute('''CREATE TABLE IF NOT EXISTS patients
                 (id INTEGER PRIMARY KEY, hospital_id INTEGER, name TEXT, blood_group TEXT, has_cancer TEXT, has_diabetes TEXT, other_info TEXT)''')
    # Insert default admin if not exists
    try:
        default_admin_pass = generate_password_hash('adminpass')
        c.execute("INSERT INTO admins (username, password) VALUES (?, ?)", ('admin', default_admin_pass))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Already exists
    conn.close()

init_db()

# Admin Login
@app.route('/', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('healthqr.db')
        c = conn.cursor()
        c.execute("SELECT * FROM admins WHERE username=?", (username,))
        admin = c.fetchone()
        conn.close()
        if admin and check_password_hash(admin[2], password):
            session['user_id'] = admin[0]
            session['user_type'] = 'admin'
            return redirect(url_for('admin_panel'))
    return render_template('admin_login.html')

# Admin Panel: Create Hospital Accounts
@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    if 'user_type' not in session or session['user_type'] != 'admin':
        return redirect(url_for('admin_login'))
    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        conn = sqlite3.connect('healthqr.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO hospitals (name, username, email, password) VALUES (?, ?, ?, ?)", (name, username, email, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username or email already exists!"
        conn.close()
        return redirect(url_for('admin_panel'))
    
    # List all hospitals
    conn = sqlite3.connect('healthqr.db')
    c = conn.cursor()
    c.execute("SELECT id, name, username, email FROM hospitals")
    hospitals = c.fetchall()
    conn.close()
    return render_template('admin_panel.html', hospitals=hospitals)

# Hospital Login
@app.route('/hospital_login', methods=['GET', 'POST'])
def hospital_login():
    if request.method == 'POST':
        email = request.form['email']           # ← Ab email se login
        password = request.form['password']
        
        conn = sqlite3.connect('healthqr.db')
        c = conn.cursor()
        c.execute("SELECT id, password FROM hospitals WHERE email = ?", (email,))
        hospital = c.fetchone()
        conn.close()

        if hospital and check_password_hash(hospital[1], password):
            session['user_id'] = hospital[0]
            session['user_type'] = 'hospital'
            return redirect(url_for('hospital_panel'))
        else:
            return '''
            <div style="text-align:center; margin-top:100px;">
                <h2 style="color:#ff4444;">❌ Invalid Email or Password</h2>
                <p><a href="/hospital_login" style="color:#00c853; font-size:20px;">← Try Again</a></p>
            </div>
            '''

    return render_template('hospital_login.html')

# Hospital Panel: Add Patients and Generate QR
@app.route('/hospital', methods=['GET', 'POST'])
def hospital_panel():
    if 'user_type' not in session or session['user_type'] != 'hospital':
        return redirect(url_for('hospital_login'))
    hospital_id = session['user_id']
    
    if request.method == 'POST':
        name = request.form['name']
        blood_group = request.form['blood_group']
        has_cancer = request.form['has_cancer']
        has_diabetes = request.form['has_diabetes']
        other_info = request.form['other_info']
        
        # Save patient
        conn = sqlite3.connect('healthqr.db')
        c = conn.cursor()
        c.execute("INSERT INTO patients (hospital_id, name, blood_group, has_cancer, has_diabetes, other_info) VALUES (?, ?, ?, ?, ?, ?)",
                  (hospital_id, name, blood_group, has_cancer, has_diabetes, other_info))
        patient_id = c.lastrowid
        conn.commit()
        conn.close()
        
        # Generate QR data (JSON)
        patient_data = {
            'patient_id': patient_id,
            'name': name,
            'blood_group': blood_group,
            'has_cancer': has_cancer,
            'has_diabetes': has_diabetes,
            'other_info': other_info
        }
        qr_data = json.dumps(patient_data)
        
        # Generate QR image
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        
        # Send QR as downloadable image
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        return send_file(img_io, mimetype='image/png', as_attachment=True, download_name=f'patient_{patient_id}_qr.png')
    
    # List patients for this hospital
    conn = sqlite3.connect('healthqr.db')
    c = conn.cursor()
    c.execute("SELECT id, name, blood_group, has_cancer, has_diabetes, other_info FROM patients WHERE hospital_id=?", (hospital_id,))
    patients = c.fetchall()
    conn.close()
    return render_template('hospital_panel.html', patients=patients)

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    app.run(debug=True)
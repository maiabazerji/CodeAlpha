from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import re
from flask import jsonify

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Use a more secure key in production

# In-memory user storage for demonstration purposes
users = {'admin': generate_password_hash('password123')}

# Home Page
@app.route('/')
def home():
    return render_template('index.html')

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            return redirect(url_for('message'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

# Message Page
@app.route('/message')
def message():
    if 'username' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('message.html', username=session['username'])

@app.route('/submit', methods=['POST'])
def submit_feedback():
    message = request.form.get('message')
    if message:
        # Process the message as needed
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from bson.objectid import ObjectId

app = Flask(__name__)
app.config['MONGO_URI'] = "mongodb://localhost:27017/yourdbname"
app.secret_key = 'your_secret_key'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# Home route
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        users = mongo.db.users
        existing_user = users.find_one({'username': request.form['username']})

        if existing_user is None:
            hashpass = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
            users.insert_one({'username': request.form['username'], 'password': hashpass, 'role': 'user'})
            session['username'] = request.form['username']
            return redirect(url_for('dashboard'))

        flash('That username already exists!')
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = mongo.db.users
        login_user = users.find_one({'username': request.form['username']})

        if login_user:
            if bcrypt.check_password_hash(login_user['password'], request.form['password']):
                session['username'] = request.form['username']
                session['role'] = login_user['role']
                return redirect(url_for('dashboard'))

        flash('Invalid username/password combination')
    return render_template('login.html')

# Dashboard route (protected)
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'], role=session['role'])
    return redirect(url_for('login'))

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Role-based route (example)
@app.route('/admin')
def admin():
    if 'username' in session and session['role'] == 'admin':
        return 'Admin Dashboard'
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)

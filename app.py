from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

# Create the database
with app.app_context():
    db.create_all()

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
            return "Username already exists!"

        new_user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template('register.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return "Invalid username or password!"

        session['username'] = username
        return redirect(url_for("vote"))

    return render_template('login.html')

@app.route("/vote")
def vote():
    if 'username' not in session:
        return redirect(url_for("login"))
    return render_template('vote.html', username=session['username'])

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for("home"))

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)
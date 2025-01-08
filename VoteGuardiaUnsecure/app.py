from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import helpers_func as helpers_func
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

#Init le rsa
helpers_func.rsa_init()


# Table electeurs
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    vote_count = db.Column(db.Integer, nullable=False, default=0)

# Table votes
class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_vote = db.Column(db.Text, nullable=False)
    encrypted_aes_key = db.Column(db.Text, nullable=False)
    hmac_value = db.Column(db.Text, nullable=False)

# Create all tables 
with app.app_context():
    # On demare avec une app vide
    db.create_all()
    db.drop_all()
    db.create_all()

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
            return "Username already exists!"

        new_user = User(username=username, password_hash=hashlib.md5(password.encode()).hexdigest())
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
        if not user or not hashlib.md5(password.encode()).hexdigest() == user.password_hash:
            return "Invalid username or password!"

        session['username'] = username
        session['user_id'] = user.id

        return redirect(url_for("vote"))

    return render_template('login.html')


@app.route("/bruteHmac", methods=["POST"])
def bruteHmac():
    if request.method =="POST":
        plaintext = request.form.get("plaintext")
        hmac = request.form.get("hmac")
        with open("static/toppass.txt", "r") as f:
            keylist = f.readlines()
        for key in keylist:
            key = key.strip()
            try_hmac = helpers_func.generate_hmac(key.encode(), plaintext.encode())
            if try_hmac.hex() == hmac:
                return jsonify({"Status" : "success", "key":key})
        return jsonify({"Status" : "fail"})


@app.route("/vote", methods=["GET", "POST"])
def vote():
    if 'username' not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        
        choice = request.form.get("vote").split(":")[1]  # 'croissant' | 'chocolatine'
        user_id = session['user_id']
        user = User.query.filter_by(id=user_id).first()
        if user.vote_count >= 1:
            return render_template('vote.html', username=session['username'], messages=flash('You already voted', 'danger'))

        # Gen key AES pour le vote
        aes_key = helpers_func.generate_aes_key()

        # Chiffre le vote
        encrypted_vote = helpers_func.encrypt_with_aes(aes_key, choice)
        print(f"Using RSA key {helpers_func.server_public_key}")
        # "protege" la clée du client
        encrypted_aes_key = helpers_func.encrypt_aes_key_with_rsa(aes_key, helpers_func.server_public_key)

        # Genere hmac pour anti tamper
        vote_hmac = helpers_func.generate_hmac(aes_key, encrypted_vote.hex().encode())

        # On stocke le tout
        
        user.vote_count += 1
        new_vote = Vote(
            user_id=user_id,
            encrypted_vote=encrypted_vote.hex(), 
            encrypted_aes_key=encrypted_aes_key.hex(),
            hmac_value=vote_hmac.hex()
        )
        db.session.add(new_vote)
        db.session.commit()

        return render_template('vote.html', username=session['username'], messages=flash(f'Vote submited for {choice}', 'success'))

    return render_template('vote.html', username=session['username'])


@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for("home"))

@app.route("/results")
def results():
    """
    This endpoint is more meant to show how the server decrypt and "count" the votes
    However using such method irl is risky and doesnt follow guidelines of what
    could be qualified as a "democratic" vote, because voter secrecy isnt guaranteed at all
    and there is no security measure if there is a compromission somewhere in the chain of trust
    """
    votes_data = []
    all_votes = Vote.query.all()

    for v in all_votes:
        
        encrypted_vote_bytes = bytes.fromhex(v.encrypted_vote)
        encrypted_aes_key_bytes = bytes.fromhex(v.encrypted_aes_key)
        hmac_bytes = bytes.fromhex(v.hmac_value)
        
        aes_key = helpers_func.decrypt_aes_key_with_rsa(encrypted_aes_key_bytes, helpers_func.server_private_key)

        try:
            helpers_func.verify_hmac(aes_key, encrypted_vote_bytes, hmac_bytes)
            integrity_status = "OK"
        except Exception as e:
            integrity_status = f"FAILED: {e}"

        # Decrypt the vote
        decrypted_vote = helpers_func.decrypt_with_aes(aes_key, encrypted_vote_bytes)

        votes_data.append({
            'user_id': v.user_id,
            'decrypted_vote': decrypted_vote,
            'integrity': integrity_status,
            'encrypted_vote': v.encrypted_vote,
            'hmac':v.hmac_value
        })

    return render_template('results.html', votes=votes_data, n=helpers_func.n_public)

@app.route("/leakpasswords")
def leakpasswords():
    """
    This endpoint is used to demonstrate password weakness
    """
    user_data = []
    all_users = User.query.all()

    for v in all_users:
        

        user_data.append({
            'username': v.username,
            'password': v.password_hash
        })

    return render_template('passwords.html', users=user_data)

@app.route("/vulns")
def vulns():
    """
    This endpoint is used to demonstrate password weakness
    """
    return render_template('vulns.html')

@app.route('/')
def home():
    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)
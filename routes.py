import base64
from flask import render_template, url_for,redirect, flash, make_response, request 
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_login import login_user, LoginManager, login_required, logout_user
import flask_login
from app import app, db
from forms import *
from models import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCKSIZE = 16
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["50/day", "10/minute", "1/second"]
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/dashboard/view/<int:id>', methods=['GET','POST'])
@login_required
def show(id):
    form = PasForm()
    username = flask_login.current_user.username
    if form.validate_on_submit():
        crypt = Bcrypt()
        user = User.query.filter_by(username=username).first()
        if crypt.check_password_hash(user.password, form.password.data):
            secret = Psswd.query.get_or_404(id)
            key = SHA256.new(form.password.data.encode()).digest()
            cipher = AES.new(key, AES.MODE_CBC, base64.b64decode(secret.iv))
            decrypted = unpad(cipher.decrypt(secret.password), BLOCKSIZE)
            flash(f"Decrypted password  is {decrypted.decode()}. ")
            return redirect(url_for("dashboard"))
        else:
            flash("Wrong master password.")
    else:
        flash(form.msg)
    return render_template("show.html", form = form)


@app.route('/dashboard/delete/<int:id>')
@login_required
def delete(id):
    pswd_to_del = Psswd.query.get_or_404(id)
    username = flask_login.current_user.username

    try:
        if pswd_to_del.username != username:
            raise Exception("Unable to delete password.")
        db.session.delete(pswd_to_del)
        db.session.commit()
        flash("Password successfully deleted!")
       
    except Exception:
        flash("Unable to delete password.")
    finally:
        return redirect(url_for("dashboard"))


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():

    user = flask_login.current_user.username
    passwrd_list = Psswd.query.filter_by(username = user).all()

    
    return render_template("dashboard.html", passwrd_list = passwrd_list)


@app.route('/dashboard/add', methods=['GET', 'POST'])
@login_required
def dashboard_add():
    form = AddPsswdForm()
    username = flask_login.current_user.username

    if form.validate_on_submit():
        crypt = Bcrypt()
        user = User.query.filter_by(username=username).first()
        if crypt.check_password_hash(user.password, form.master_password.data):
            sha = SHA256.new(form.master_password.data.encode())
            iv = get_random_bytes(BLOCKSIZE)
            cipher = AES.new(sha.digest(), AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(form.password.data.encode(), BLOCKSIZE))
            new_psswd = Psswd(em = form.em.data, username =username,
             site_adress = form.site_adress.data, password = encrypted,
             iv= base64.b64encode(iv)  )
            db.session.add(new_psswd)
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash("Wrong master password.")
    else:
        flash(form.msg)

    return render_template("dashboard_add.html", form = form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        crypt = Bcrypt()
        hash = crypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password = hash)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    else:
        flash(form.msg)

    return render_template('register.html', form = form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            bcrypt = Bcrypt()
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                resp = make_response(redirect(url_for("dashboard")))
                resp.set_cookie('username', user.username.encode(), secure=True)
                return resp
            else:
                flash("Wrong username or password.")
        else:
            flash("Wrong username or password.")


    return render_template('login.html', form = form)

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    form = ForgetForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash(f"Normally there would be a reset email sent to {form.em.data}")
        else:
            flash(form.msg)

    return render_template('forgot.html', form = form)

@app.route('/')
def home():
    return render_template('startpage.html')
from flask import render_template, url_for,redirect, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_login import login_user, LoginManager, login_required, logout_user
from app import app, db
from forms import *
from models import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

bcrypt = Bcrypt()

BLOCK_SIZE = 16

usr_name = ""
key = b""
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


@app.route('/dashboard/delete/<int:id>')
def delete(id):
    pswd_to_del = Psswd.query.get_or_404(id)

    try:
        db.session.delete(pswd_to_del)
        db.session.commit()
        flash("Password successfully deleted!")
       
    except:
        flash("Unable to delete password.")
    finally:
        passwrd_list = Psswd.query.filter_by(username = usr_name).all()
        if passwrd_list:
            cipher = AES.new(key, AES.MODE_ECB)
            for el in passwrd_list:
                el.password = unpad(cipher.decrypt(el.password), BLOCK_SIZE).decode()
        return render_template("dashboard.html", passwrd_list = passwrd_list)

# @app.route('/dashboard/update/<int:id>')
# def update(id):
#     pswd_to_up = Psswd.query.filter_by(id = id).first()

#     try:
#         pswd_to_up
#         db.session.commit()
#         flash("Password successfully deleted!")
       
#     except:
#         flash("Unable to delete password.")
#     finally:
#         passwrd_list = Psswd.query.filter_by(username = usr_name).all()
#         if passwrd_list:
#             cipher = AES.new(key, AES.MODE_ECB)
#             for el in passwrd_list:
#                 el.password = unpad(cipher.decrypt(el.password), BLOCK_SIZE).decode()
#         return render_template("dashboard.html", passwrd_list = passwrd_list)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    global usr_name
    global key
    usr_name = ""
    key = b""
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    passwrd_list = Psswd.query.filter_by(username = usr_name).all()
    if passwrd_list:
        cipher = AES.new(key, AES.MODE_ECB)
        for el in passwrd_list:
            el.password = unpad(cipher.decrypt(el.password), BLOCK_SIZE).decode()
    return render_template("dashboard.html", passwrd_list = passwrd_list)


@app.route('/dashboard/add', methods=['GET', 'POST'])
@login_required
def dashboard_add():
    form = AddPsswdForm()

    if form.validate_on_submit():
        data_padded = pad( form.password.data.encode(), BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_ECB)
        new_psswd = Psswd(em = form.em.data, username = usr_name,site_adress = form.site_adress.data,
         password = cipher.encrypt(data_padded))
        db.session.add(new_psswd)
        db.session.commit()

        return redirect(url_for('dashboard'))

    return render_template("dashboard_add.html", form = form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hash = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password = hash)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    else:
        flash(form.msg)

    return render_template('register.html', form = form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    global usr_name
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                after_login(form.username.data, form.password.data)
                return redirect(url_for('dashboard'))
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

def after_login(name, master):
    global key
    global usr_name
    usr_name = name
    key = pad(master.encode(), BLOCK_SIZE)
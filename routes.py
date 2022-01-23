from flask import render_template, url_for,redirect, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_login import login_user, LoginManager, login_required, logout_user
from app import app, db
from forms import *
from models import *

bcrypt = Bcrypt()


limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["50 per day", "5 per minute", "1 per second"]
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('startpage.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template("dashboard.html")


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
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
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
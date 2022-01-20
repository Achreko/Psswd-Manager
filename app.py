from flask import Flask, render_template, url_for
from db_storage import *

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'test'

db.init_app(app)

@app.route('/')
def home():
    return render_template('startpage.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    return render_template('register.html', form = form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    return render_template('login.html', form = form)

if __name__ == '__main__':
    app.run(ssl_context=('cert/test.crt', 'cert/test.key'), debug=True )
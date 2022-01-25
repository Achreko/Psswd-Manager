from app import db
from flask_login import UserMixin
from flask_bcrypt import Bcrypt

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Psswd(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    em = db.Column(db.String(40), nullable=False)
    username = db.Column(db.String(20), nullable=False)
    site_adress = db.Column(db.String(50),  nullable=False)
    password = db.Column(db.String(100), nullable=False)
    iv = db.Column(db.String(100), nullable=False)


def clear_data():
    db.drop_all()
    db.create_all()
    bcrypt = Bcrypt()
    hash = bcrypt.generate_password_hash("kochamPW#1")
    new_user = User(username="test645", password = hash)
    db.session.add(new_user)
    db.session.commit()
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
import re

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min = 7, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min = 7, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        exitsting_users = User.query.filter_by(
            username = username.data).first()

        if exitsting_users:
            raise ValidationError(
                "This username is already taken. Please choose a different one.")
    
    def validate_password(self, password):
        if  password.data.isalnum() or \
        re.search(r"[A-Z]+", password.data) == None or \
        re.search(r"[0-9]", password.data) == None:
            raise ValidationError(
                "Password has to contain at least 1 digit, uppercase letter and nonalphanumeric character.")
  

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min = 5, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min = 5, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")
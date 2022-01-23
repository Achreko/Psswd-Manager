from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Email, InputRequired, Length, ValidationError
import re
from flask_wtf import FlaskForm
from models import *

class RegistrationForm(FlaskForm):
    msg = ""
    username = StringField(validators=[InputRequired(), Length(min = 7, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min = 7, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        exitsting_users = User.query.filter_by(
            username = username.data).first()

        if exitsting_users:
            self.msg = "This username is already taken. Please choose a different one."
            raise ValidationError(
                "This username is already taken. Please choose a different one.")
    
    def validate_password(self, password):
        if  password.data.isalnum() or \
        re.search(r"[A-Z]+", password.data) == None or \
        re.search(r"[0-9]", password.data) == None:
            self.msg = "Password has to contain at least 1 digit, uppercase letter and nonalphanumeric character."
            raise ValidationError(
                "Password has to contain at least 1 digit, uppercase letter and nonalphanumeric character.")
  

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min = 5, max=40)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min = 5, max=25)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


class AddPsswdForm(FlaskForm):
    site_adress = StringField(validators=[InputRequired(), Length(min = 5, max=20)], render_kw={"placeholder": "Site adress"})
    password = PasswordField(validators=[InputRequired(), Length(min = 5, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Add to vault")

class ForgetForm(FlaskForm):
    msg = ""
    em = StringField(validators=[InputRequired(), Length(min = 7, max=40), Email() ], render_kw={"placeholder": "Email"})
    username = StringField(validators=[InputRequired(), Length(min = 7, max=20)], render_kw={"placeholder": "Username"})

    def validate_username(self, username):
        exitsting_users = User.query.filter_by(
            username = username.data).first()

        if not exitsting_users:
            self.msg = "There is no user with that username."
            raise ValidationError(
                "There is no user with that username.")

    submit = SubmitField("Send reset link")
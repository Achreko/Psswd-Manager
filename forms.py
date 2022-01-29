from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import Email, InputRequired, Length, ValidationError
import re
from flask_wtf import FlaskForm
from models import *

class RegistrationForm(FlaskForm):
    msg = ""
    username = StringField(validators=[InputRequired(), Length(min = 7, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min = 7, max=32)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        if  username.data.find("<") != -1 or \
            username.data.find(">") != -1:
            self.msg = "Username cannot contain '<' and '>' symbols."
            raise ValidationError(
                "Username cannot contain '<' and '>' symbols.")
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
        if  password.data.find("<") != -1 or \
            password.data.find(">") != -1:
            self.msg = "Password cannot contain '<' and '>' symbols."
            raise ValidationError(
                "Password cannot contain '<' and '>' symbols.")
  

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min = 5, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min = 5, max=32)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")
    def validate_username(self, username):
        if  username.data.find("<") != -1 or \
            username.data.find(">") != -1:
            self.msg = "Username cannot contain '<' and '>' symbols."
            raise ValidationError(
                "Username cannot contain '<' and '>' symbols.")
    def validate_password(self, password):
        if  password.data.find("<") != -1 or \
            password.data.find(">") != -1:
            self.msg = "Password cannot contain '<' and '>' symbols."
            raise ValidationError(
                "Password cannot contain '<' and '>' symbols.")



class AddPsswdForm(FlaskForm):
    msg = ""
    em = EmailField(validators=[InputRequired(), Length(min = 7, max=40), Email()], render_kw={"placeholder": "Email adress"})
    site_adress = StringField(validators=[InputRequired(), Length(min = 5, max=20)], render_kw={"placeholder": "Site adress"})
    password = PasswordField(validators=[InputRequired(), Length(min = 5, max=20)], render_kw={"placeholder": "Password"})
    master_password = PasswordField(validators=[InputRequired(), Length(min = 5, max=32)], render_kw={"placeholder": "Master Password"})
    submit = SubmitField("Add to vault")

    def validate_em(self, em):
        if  em.data.find("<") != -1 or \
            em.data.find(">") != -1:
            self.msg = "No field can contain '<' and '>' symbols."
            raise ValidationError(
                "No field can contain '<' and '>' symbols.")
    def validate_password(self, password):
        if  password.data.find("<") != -1 or \
            password.data.find(">") != -1:
            self.msg = "No field can contain '<' and '>' symbols."
            raise ValidationError(
                "No field can contain '<' and '>' symbols.")


class ForgetForm(FlaskForm):
    msg = ""
    em = EmailField(validators=[InputRequired(), Length(min = 7, max=40), Email() ], render_kw={"placeholder": "Email"})
    username = StringField(validators=[InputRequired(), Length(min = 7, max=20)], render_kw={"placeholder": "Username"})

    def validate_username(self, username):
        exitsting_users = User.query.filter_by(
            username = username.data).first()

        if not exitsting_users:
            self.msg = "There is no user with that username."
            raise ValidationError(
                "There is no user with that username.")

    submit = SubmitField("Send reset link")
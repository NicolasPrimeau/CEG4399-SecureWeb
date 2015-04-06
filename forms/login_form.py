from flask_wtf import Form
from wtforms import TextField, PasswordField

class LoginForm(Form):
    username = TextField('Username')
    password = PasswordField('Password')   
    

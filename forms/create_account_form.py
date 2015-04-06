from flask_wtf import Form
from flask_wtf.html5 import EmailField, IntegerField
from wtforms import TextField, PasswordField

class CreateAccountForm(Form):
    Email = EmailField("Email address")
    User = TextField('Username')
    Password = PasswordField('Password')   
    Confirm_Password = PasswordField('Confirm Password')
    Name = TextField('Name')
    Age = IntegerField('Age')
    

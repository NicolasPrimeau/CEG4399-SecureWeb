from flask_wtf import Form
from wtforms import PasswordField

class RecoverPasswordForm(Form):
    Password = PasswordField('Password')   
    Confirm_Password = PasswordField('Confirm Password')  
    

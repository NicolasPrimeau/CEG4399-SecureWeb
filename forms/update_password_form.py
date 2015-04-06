from flask_wtf import Form
from wtforms import PasswordField

class UpdatePasswordForm(Form):
    old_password = PasswordField('Old Password')
    Password = PasswordField('Password')   
    Confirm_Password = PasswordField('Confirm Password')  
    

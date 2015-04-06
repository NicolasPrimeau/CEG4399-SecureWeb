from flask_wtf import Form
from wtforms import TextAreaField

class PublicKeyUpload(Form):
    public_key = TextAreaField()

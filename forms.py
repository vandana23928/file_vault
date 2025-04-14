from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, FileField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    password2 = PasswordField(
        "Repeat Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Sign In")

class UploadForm(FlaskForm):
    file = FileField("Choose File or Folder (zip folder for folder encryption)", validators=[DataRequired()])
    use_password = BooleanField("Enable Password Encryption")
    password = PasswordField("Encryption Password (if enabled)")
    submit = SubmitField("Encrypt and Upload")

class DecryptForm(FlaskForm):
    file = FileField("Choose Encrypted File", validators=[DataRequired()])
    password = PasswordField("Password (if used for encryption)")
    submit = SubmitField("Decrypt File")



class ShareForm(FlaskForm):
    recipient_email = StringField("Recipient Email", validators=[DataRequired(), Email()])
    message = TextAreaField("Message")
    file = FileField("Encrypted File", validators=[DataRequired()])
    submit = SubmitField("Share Encrypted File")

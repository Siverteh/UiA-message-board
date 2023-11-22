from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp

#Registration form contains username, password, and confirm password fields
class RegistrationForm(FlaskForm):
    #Username is a string field that is required to be filled out.
    username = StringField('Username', validators=[DataRequired()])
    #Password is a password field that has to be filled out, be atleast 8 characters long, and must include atleast one uppercase, lowercase, digit, and special character
    password = PasswordField('Password', id='password', validators=[
    DataRequired(),
    EqualTo('confirm', message='Passwords must match'),
    Length(min=8, message='Password must be at least 8 characters long'),
    Regexp(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_])', message='Password must include atleast one uppercase, lowercase, digit, and special character')
    ])
    #Confirm is a password field that is required to be filled out.
    confirm = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

#Login form contains username and password fields.
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

#TOTP form contains TOTP code field.
class TOTPForm(FlaskForm):
    totp_code = StringField('TOTP Code', validators=[DataRequired()])
    submit = SubmitField('Verify')

#Message form contains title and content fields.
class MessageForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')

#Comment form contains content field.
class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Post Comment')

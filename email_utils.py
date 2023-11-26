from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
from flask import current_app, render_template
from utility.extensions import mail

# Function to send emails
def send_email(to, subject, template, **kwargs):
    msg = Message(
        subject,
        recipients=[to],
        html=render_template(template + '.html', **kwargs),
        sender=current_app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

# Function to generate a confirmation token
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])

# Function to confirm a token
def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=current_app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

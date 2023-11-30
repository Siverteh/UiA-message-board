from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
from flask import current_app, render_template
from utility.extensions import mail
from smtplib import SMTPServerDisconnected

#Function to send emails to users.
def send_email(to, subject, template, **kwargs):
    msg = Message(
        subject,
        recipients=[to],
        html=render_template(template + '.html', **kwargs),
        sender=current_app.config['MAIL_DEFAULT_SENDER']
    )

    try:
        mail.send(msg)
    except SMTPServerDisconnected:
        #Print the exeption if the smpt server could not connect.
        print("SMTP server disconnected. Email not sent.")
    except Exception as e:
        #Print other potential exceptions.
        print(f"An error occurred: {e}")

#Function to generate a confirmation token.
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])

#Function to confirm a confirmation token.
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

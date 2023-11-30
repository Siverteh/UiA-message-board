# config.py
import os
from datetime import timedelta
from jinja2 import select_autoescape

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'skallesverd5')
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///messageboard.db')
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_TYPE = 'filesystem'
    SQLALCHEMY_ECHO = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    # Enable secure cookies when running over HTTPS
    SESSION_COOKIE_SECURE = True
    # Jinja2 autoescape configuration
    JINJA_ENV_AUTOESCAPE = select_autoescape(enabled_extensions=(), default=True)
    SECURITY_PASSWORD_SALT = "803353e1c98a504e217a839c27f96182e8977aafb5c87275"

    # Email configuration
    MAIL_SERVER = 'smtp.sendgrid.net'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'apikey'  # This is literally the string 'apikey'
    MAIL_PASSWORD = 'SendGrid API key should be here'  # Your SendGrid API key
    MAIL_DEFAULT_SENDER = 'uiamessageboard@gmail.com'  # Email verified with SendGrid

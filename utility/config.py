# config.py
import os
from datetime import timedelta
from jinja2 import select_autoescape
import secrets

class Config:
    #Set the secret key for the project
    SECRET_KEY = secrets.token_urlsafe(50)
    #Set up the database URI
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///messageboard.db')
    #Set session cookies to HTTPONLY.
    SESSION_COOKIE_HTTPONLY = True
    #Set session cookie samesite to lax.
    SESSION_COOKIE_SAMESITE = 'Lax'
    #Set the session type to filesystem.
    SESSION_TYPE = 'filesystem'
    SQLALCHEMY_ECHO = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    #Enable secure cookies when running over HTTPS
    SESSION_COOKIE_SECURE = True
    #Jinja2 autoescape configuration
    JINJA_ENV_AUTOESCAPE = select_autoescape(enabled_extensions=(), default=True)
    SECURITY_PASSWORD_SALT = "803353e1c98a504e217a839c27f96182e8977aafb5c87275"

    #Email configuration
    MAIL_SERVER = 'smtp.sendgrid.net'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'apikey'  # This is literally the string 'apikey'
    MAIL_PASSWORD = 'SendGrid API key should be here'  # Your SendGrid API key
    MAIL_DEFAULT_SENDER = 'uiamessageboard@gmail.com'  # Email verified with SendGrid

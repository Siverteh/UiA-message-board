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
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
    # Jinja2 autoescape configuration
    JINJA_ENV_AUTOESCAPE = select_autoescape(enabled_extensions=(), default=True)

    # Add any additional configuration parameters here

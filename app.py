from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from jinja2 import select_autoescape
import os
from flask_bcrypt import Bcrypt
from flask_session import Session
from datetime import timedelta

app = Flask(__name__)
bcrypt = Bcrypt(app)

#Configure database URI:
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messageboard.db'
#Secret key for signing cookies:
app.config['SECRET_KEY'] = 'skallesverd5'
#No scripts can access cookies:
app.config['SESSION_COOKIE_HTTPONLY'] = True
#Strictly enforce SameSite cookie policy:
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
#Use filesystem for session storage:
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
#Only send cookies over HTTPS:
#app.config['SESSION_COOKIE_SECURE'] = True
#Autoescape all Jinja templates:
app.jinja_env.autoescape = select_autoescape(enabled_extensions=(), default=True)

app.config['SQLALCHEMY_ECHO'] = True

#Set session lifetime to 30 minutes:
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)

#Initialize flask migrate:
migrate = Migrate(app, db)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Import routes after initializing db and login_manager to avoid circular imports
from routes import *

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

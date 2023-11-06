from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from threading import Thread
from jinja2 import select_autoescape
from hackerman import steal_cookie, steal_user_information

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = 'mysecret'
#Uncomment to turn off httponly safeguard:
app.config['SESSION_COOKIE_HTTPONLY'] = True
#Uncomment to turn off autoescape safeguard:
app.jinja_env.autoescape = select_autoescape(enabled_extensions=(), default=True)

db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def run_app():
    with app.app_context():
        db.drop_all()
        db.create_all()
    app.run(port=5000)

# Import routes after initializing db and login_manager to avoid circular imports
from routes import *

if __name__ == '__main__':
    #Uncomment all t2 to run steal_cookie.py cookie stealing web server.
    #Uncomment all t3 to run steal_user_information.py user information stealing web server.

    t1 = Thread(target=run_app)
    #t2 = Thread(target=steal_cookie.run_stealing_cookie_app)
    #t3 = Thread(target=steal_user_information.run_stealing_user_information_app)

    t1.start()
    #t2.start()
    #t3.start()

    t1.join()
    #t2.join()
    #t3.join()

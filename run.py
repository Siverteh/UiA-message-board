from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from jinja2 import select_autoescape
from flask_bcrypt import Bcrypt
from flask_session import Session
from datetime import timedelta

app = Flask(__name__)
bcrypt = Bcrypt(app)

#Configure database URI:
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messageboard.db'
#Secret key for signing cookies:
app.config['SECRET_KEY'] = 'top secret!'
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

@app.after_request
def apply_csp(response):
    #Set Content Security Policy headers to enhance security by defining where resources can be loaded from.
    csp_policy = (
        f"default-src 'self';" #Only allow resources from the same origin.
        f"script-src 'self';" #Only allow scripts from the same origin.
        f"style-src 'self';"  #Only allow styles from the same origin.
        f"img-src 'self' data:;" #Only allow images from the same origin.
        f"object-src 'none';" #Don't allow any resources to be loaded using object, embed or applet tags.
    )
    #Apply the CSP policy to the headers of the response
    response.headers['Content-Security-Policy'] = csp_policy
    response.headers['X-Content-Security-Policy'] = csp_policy
    response.headers['X-WebKit-CSP'] = csp_policy
    return response

db = SQLAlchemy(app)

#Initialize flask migrate:
migrate = Migrate(app, db)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from app.routes.auth import auth_bp
from app.routes.messages import messages_bp
app.register_blueprint(auth_bp)
app.register_blueprint(messages_bp)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

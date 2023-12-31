from flask import Flask
from utility.config import Config
from utility.extensions import db, bcrypt, login_manager, limiter, migrate, session, mail
from routes.auth_routes import auth_bp
from routes.message_routes import message_bp
from routes.error_routes import error_bp
from routes.main_routes import main_bp
from routes.oauth2_routes import oauth2_bp
from utility.populate_database import populate_database
from models import load_user

# Function to create the Flask app
def create_app(config_class=Config):
    #Initialize the core application
    app = Flask(__name__)

    #Application Configuration from config.py
    app.config.from_object(config_class)

    #Initialize database.
    db.init_app(app)
    #Initialize bcrypt.
    bcrypt.init_app(app)
    #Initialize login manager.
    login_manager.init_app(app)
    #Initialize limiter.
    limiter.init_app(app)
    #Initialize database migration.
    migrate.init_app(app, db)
    #Initialize session.
    session.init_app(app)
    #Initialize mail service.
    mail.init_app(app)

    #Register route blueprints main, auth, oauth2, message, and error.
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(oauth2_bp, url_prefix='/oauth2')
    app.register_blueprint(message_bp, url_prefix='/messages')
    app.register_blueprint(error_bp, url_prefix='/errors')

    #Route for the CSP header, makes all after requests follow the CSP header. Cannot be in singular blueprint.
    @app.after_request
    def apply_csp(response):
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "frame-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/;"
        )
        response.headers['Content-Security-Policy'] = csp_policy
        response.headers['X-Content-Security-Policy'] = csp_policy
        response.headers['X-WebKit-CSP'] = csp_policy
        return response

    return app

#Instantiate the app using the create_app function
app = create_app()

#Recreate the database and populate it with the information from populate_database.py.
with app.app_context():
    db.drop_all()
    db.create_all()
    populate_database()

#Run the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context=('self-signed_ssl_certificate/localhost.crt', 'self-signed_ssl_certificate/localhost.key'), debug=True)

# app.py
from flask import Flask
from config import Config
from extensions import db, bcrypt, login_manager, limiter, migrate, session
from routes.auth_routes import auth_bp
from routes.message_routes import message_bp
from routes.error_routes import error_bp
from routes.main_routes import main_bp

# Function to create the Flask app
def create_app(config_class=Config):
    # Initialize the core application
    app = Flask(__name__)

    # Application Configuration
    app.config.from_object(config_class)

    # Initialize plugins
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    migrate.init_app(app, db)
    session.init_app(app)

    # Register Blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(message_bp, url_prefix='/messages')
    app.register_blueprint(error_bp, url_prefix='/errors')

    # Route for the CSP header
    @app.after_request
    def apply_csp(response):
        # Set Content Security Policy headers to enhance security by defining where resources can be loaded from.
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none';"
        )
        # Apply the CSP policy to the headers of the response
        response.headers['Content-Security-Policy'] = csp_policy
        response.headers['X-Content-Security-Policy'] = csp_policy
        response.headers['X-WebKit-CSP'] = csp_policy
        return response

    return app

# Instantiate the app using the create_app function
app = create_app()

# Run the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

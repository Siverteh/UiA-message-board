from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from models import db, OAuthClient, AuthorizationCode, AccessToken, User
from forms import LoginForm, RegistrationForm, TOTPForm
from io import BytesIO
import base64
import pytz
from extensions import limiter
from authlib.integrations.flask_client import OAuth
from flask import current_app as app
import uuid
from datetime import timedelta, datetime

oauth2_bp = Blueprint('oauth2', __name__)

#Initialize OAuth
oauth = OAuth(app)

#Configure Google OAuth2 client
google = oauth.register(
    name='google',
    client_id='989959871090-tto4coh3e2qa1kri3irtrg3v419ck7gj.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

#Route for logging in with Google.
@oauth2_bp.route('/login/google')
def google_login():
    #Check if the current user is already authenticated.
    if current_user.is_authenticated:
        #If authenticated, redirect to the main index page.
        return redirect(url_for('main.index'))

    #Define the redirect URI for the OAuth2 callback.
    redirect_uri = url_for('oauth2.google_authorize', _external=True)

    #Redirect the user to the Google authorization URL.
    return google.authorize_redirect(redirect_uri)


@oauth2_bp.route('/callback')
def google_authorize():
    #Nested function to generate a unique username for google users.
    def generate_unique_username(base_username):
        username = base_username
        counter = 1
        #Checks if the username exists and appends a number to make it unique.
        while User.query.filter_by(username=username).first() is not None:
            username = f"{base_username}_{counter}"
            counter += 1
        return username

    #Exchange the authorization code for an access token.
    token = google.authorize_access_token()
    if not token:
        #If no token is received, show an error message and redirect to login.
        flash('Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        ), 'danger')
        return redirect(url_for('auth.login'))

    # Fetch the user information from Google.
    resp = google.get('userinfo')
    user_info = resp.json()

    # Check if the user with the provided Google id already exist.
    user = User.query.filter_by(google_id=user_info['id']).first()

    if not user:
        # If the user doesn't exist, create a new user.
        user = User(
            username=generate_unique_username(user_info['name']),
            email=user_info['email'],
            google_id=user_info['id'],
        )
        user.set_totp_secret()
        db.session.add(user)
        db.session.commit()

    # Generate a unique access token for the user.
    access_token = str(uuid.uuid4())
    token_expiry = datetime.utcnow() + timedelta(hours=1)
    token = AccessToken(token=access_token, client_id=None, user_id=user.id, expires_at=token_expiry)
    db.session.add(token)
    db.session.commit()

    # Log the user in and set the access token in the session or send it to the user.
    login_user(user)

    if not user.is_2fa_setup:
        # Redirect users who haven't set up 2FA to the 2FA setup page.
        return redirect(url_for('auth.setup_2fa', user_id=user.id))
    else:
        # Redirect users who have set up 2FA to the 2FA verification page.
        session['verify_2fa'] = True
        session['username'] = user.username
        return redirect(url_for('auth.verify_2fa'))

@oauth2_bp.route('/auth', methods=['GET', 'POST'])
def authorize():
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')

    # Validate the client_id and redirect_uri
    client = OAuthClient.query.filter_by(client_id=client_id, redirect_uri=redirect_uri).first()
    if not client:
        return 'Invalid client', 400

    if request.method == 'GET':
        # Check if user is authenticated, redirect to login if not
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login', next=request.url))

        # Show a consent page to the user
        return render_template('consent.html', client=client)

    # Process user response from consent page
    if request.method == 'POST':
        consent = request.form.get('consent')
        if consent == 'approve':
            # Generate authorization code
            authorization_code = str(uuid.uuid4())
            code = AuthorizationCode(code=authorization_code, client_id=client.id, user_id=current_user.id)
            db.session.add(code)
            db.session.commit()

            # Redirect back to the client with the authorization code
            return redirect(f'{redirect_uri}?code={authorization_code}')
        else:
            # Handle denial of consent
            # Redirect or show a message as per your application's flow
            return redirect(url_for('main.index'))  # or an appropriate route



@oauth2_bp.route('/token', methods=['POST'])
def token():
    auth_code = request.form.get('code')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')

    # Validate the client credentials and authorization code
    client = OAuthClient.query.filter_by(client_id=client_id, client_secret=client_secret).first()
    if not client:
        return jsonify({'error': 'invalid_client'}), 401

    code = AuthorizationCode.query.filter_by(code=auth_code, client_id=client.id).first()
    if not code or code.expires_at < datetime.utcnow():
        return jsonify({'error': 'invalid_grant'}), 400

    # Create access token
    access_token = str(uuid.uuid4())
    token = AccessToken(token=access_token, client_id=client.id, user_id=code.user_id)
    db.session.add(token)
    db.session.commit()

    # Delete the authorization code after it's been used
    db.session.delete(code)
    db.session.commit()

    return jsonify(access_token=access_token, token_type='bearer')

@oauth2_bp.route('/protected_resource')
def protected_resource():
    auth_header = request.headers.get('Authorization')
    if auth_header:
        token_value = auth_header.split(' ')[1]
        token = AccessToken.query.filter_by(token=token_value).first()
        if token and token.expires_at > datetime.utcnow():
            # Token is valid, return protected resource
            # Replace with actual data retrieval logic
            return jsonify({'data': 'Protected resource'})
        else:
            return jsonify({'error': 'invalid_token'}), 401
    else:
        return jsonify({'error': 'authorization_header_missing'}), 401


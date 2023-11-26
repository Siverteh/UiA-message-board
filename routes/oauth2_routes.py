from flask import Blueprint, request, redirect, url_for, flash, session
from flask_login import current_user
from models import db, User
from authlib.integrations.flask_client import OAuth
from flask import current_app as app

oauth2_bp = Blueprint('oauth2', __name__)


def generate_unique_username(base_username):
    username = base_username
    counter = 1
    while User.query.filter_by(username=username).first() is not None:
        username = f"{base_username}_{counter}"
        counter += 1
    return username

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


@oauth2_bp.route('/callback/google')
def google_authorize():

    # Exchange the authorization code for a token provided by Google
    token = google.authorize_access_token()
    if not token:
        flash('Access denied: reason={} error={}'.format(
            request.args['error_reason'], request.args['error_description']), 'danger')
        return redirect(url_for('auth.login'))

    # Fetch the user information from Google
    resp = google.get('userinfo')
    user_info = resp.json()

    # Check if the user with the provided Google id already exists
    user = User.query.filter_by(google_id=user_info['id']).first()

    if not user:
        # If the user doesn't exist, create a new user
        user = User(
            username=generate_unique_username(user_info['name']),
            email=user_info['email'],
            google_id=user_info['id'],
        )
        user.set_totp_secret()
        db.session.add(user)
        db.session.commit()

    # Redirect based on whether 2FA is set up
    if not user.is_2fa_setup:
        return redirect(url_for('auth.setup_2fa', user_id=user.id))
    else:
        session['verify_2fa'] = True
        session['username'] = user.username
        return redirect(url_for('auth.verify_2fa'))

    # Redirect to a default page if none of the above conditions are met
    return redirect(url_for('main.index'))


# Configure GitHub OAuth2 client
github = oauth.register(
    name='github',
    client_id='a3f1ea3512b2e54402cb',
    client_secret='3679688d2ead516f9f9b5fb2070413fa920869d7',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'}
)

@oauth2_bp.route('/login/github')
def github_login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    redirect_uri = url_for('oauth2.github_authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

@oauth2_bp.route('/callback/github')
def github_authorize():

    # Exchange the authorization code for a token provided by GitHub
    token = github.authorize_access_token()
    if not token:
        flash('Access denied: reason={} error={}'.format(
            request.args['error_reason'], request.args['error_description']), 'danger')
        return redirect(url_for('auth.login'))

    # Fetch the user information from GitHub
    # Note: GitHub's API endpoint for user info is slightly different from Google's
    resp = github.get('user')
    user_info = resp.json()

    #Handle cases where GitHub does not provide an email
    email = user_info.get('email')
    if not email:
        # Generate a placeholder email or handle it accordingly
        email = f"{user_info['login']}@noemail.github.com"

    # Check if the user with the provided GitHub id already exists
    user = User.query.filter_by(github_id=user_info['id']).first()

    if not user:
        user = User(
            username=generate_unique_username(user_info['login']),
            email=email,
            github_id=user_info['id'],
        )
        user.set_totp_secret()
        db.session.add(user)
        db.session.commit()

    # Redirect based on whether 2FA is set up
    if not user.is_2fa_setup:
        return redirect(url_for('auth.setup_2fa', user_id=user.id))
    else:
        session['verify_2fa'] = True
        session['username'] = user.username
        return redirect(url_for('auth.verify_2fa'))

    # Redirect to a default page if none of the above conditions are met
    return redirect(url_for('main.index'))

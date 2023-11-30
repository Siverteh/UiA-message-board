from flask import Blueprint, request, redirect, url_for, flash, session
from flask_login import current_user
from models import db, User
from authlib.integrations.flask_client import OAuth
from flask import current_app as app

oauth2_bp = Blueprint('oauth2', __name__)

#Function to add a number to the end of a username if it is already in the database.
def generate_unique_username(base_username):
    #Get the base username-
    username = base_username
    #Start the counter at 1.
    counter = 1
    #Check if the current username + counter is unique, if not increment counter and try again.
    while User.query.filter_by(username=username).first() is not None:
        username = f"{base_username}_{counter}"
        counter += 1
    #Return the new unique username.
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
    #Exchange the authorization code for a token provided by Google
    token = google.authorize_access_token()
    #If you did not get a token access was denied, return the user to the login screen.
    if not token:
        flash('Access denied: reason={} error={}'.format(
            request.args['error_reason'], request.args['error_description']), 'danger')
        return redirect(url_for('auth.login'))

    #If the authorization code was validated and you got a token fetch the user information from Google
    resp = google.get('userinfo')
    user_info = resp.json()

    #Check if the user with the provided Google id already exists
    user = User.query.filter_by(google_id=user_info['id']).first()

    if not user:
        #If the user doesn't exist, create a new user.
        user = User(
            username=generate_unique_username(user_info['name']),
            email=user_info['email'],
            google_id=user_info['id'],
        )
        #Set the new useræs totp secret and add them to the database.
        user.set_totp_secret()
        db.session.add(user)
        db.session.commit()

    #Redirect to 2fa setup if they have not already set it up.
    if not user.is_2fa_setup:
        return redirect(url_for('auth.setup_2fa', user_id=user.id))
    #Else redirect them to the verification screen.
    else:
        session['verify_2fa'] = True
        session['username'] = user.username
        return redirect(url_for('auth.verify_2fa'))


#Configure GitHub OAuth2 client
github = oauth.register(
    name='github',
    client_id='a3f1ea3512b2e54402cb',
    client_secret='3679688d2ead516f9f9b5fb2070413fa920869d7',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'}
)

#Route for logging in with Google.
@oauth2_bp.route('/login/github')
def github_login():
    #If the user is already authenticated / logged in redirect them to the homepage.
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    #If not redirect them to the github_authorize route.
    redirect_uri = url_for('oauth2.github_authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

#Function to handle GitHub callbacks.
@oauth2_bp.route('/callback/github')
def github_authorize():

    #Exchange the authorization code for a token provided by GitHub
    token = github.authorize_access_token()
    #If you did not get a token access was denied, return the user to the login screen.
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
        #Generate a placeholder email
        email = f"{user_info['login']}@noemail.github.com"

    #Check if the user with the provided GitHub id already exists
    user = User.query.filter_by(github_id=user_info['id']).first()

    #If the GitHub user is not in the database add them.
    if not user:
        user = User(
            username=generate_unique_username(user_info['login']),
            email=email,
            github_id=user_info['id'],
        )
        #Set the totp secret for the user and add them to the database.
        user.set_totp_secret()
        db.session.add(user)
        db.session.commit()

    #Redirect them to 2fa setup if they have not already set up 2fa.
    if not user.is_2fa_setup:
        return redirect(url_for('auth.setup_2fa', user_id=user.id))
    #Else redirect them to the 2fa verification route.
    else:
        session['verify_2fa'] = True
        session['username'] = user.username
        return redirect(url_for('auth.verify_2fa'))

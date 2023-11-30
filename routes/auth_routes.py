from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, login_required, logout_user, current_user
from models import db, User
from forms import LoginForm, RegistrationForm, TOTPForm
import pyotp
import qrcode
from io import BytesIO
import base64
import pytz
from utility.extensions import limiter
from uuid import uuid4
from utility.email_utils import confirm_token, generate_confirmation_token, send_email
import requests

auth_bp = Blueprint('auth', __name__)

#Global variable for the local timezone.
LOCAL_TIMEZONE = pytz.timezone('Europe/Oslo')

#Function to turn the datetime to the local timezone and format it.
def format_datetime(dt):
    if dt is None:
        return None
    # Convert the datetime object to the local timezone
    local_dt = dt.replace(tzinfo=pytz.utc).astimezone(LOCAL_TIMEZONE)
    return local_dt.strftime('%H:%M:%S')

#Route to handle registration
@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def register():
    #Get the registration form
    form = RegistrationForm()

    #Ensures logged in users cant access the register page.
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    #If the request methos is GET just render the registration page.
    if request.method == 'GET':
        return render_template('auth/register.html', form=form)

    #If the forn is not validated.
    if not form.validate_on_submit():
        #Check if the error comes from the entered email og password and alert the user with the problem.
        for fieldName in form.errors.items():
            if fieldName[0] == "email":
                flash("Invalid email", 'danger')
            elif fieldName[0] == "password":
                flash("Invalid password", 'danger')
        return render_template('auth/register.html', form=form)

    #reCAPTCHA verification
    recaptcha_response = request.form['g-recaptcha-response']
    secret_key = '6LeasiApAAAAANSTr4gVeKwOFCiF8pvtOFyWUwKG'  # Use your actual secret key here
    payload = {
        'secret': secret_key,
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()

    if not result['success']:
        flash('reCAPTCHA validation failed. Please try again.', 'danger')
        return render_template('auth/register.html', form=form)

    #Check if the entered username or email already exists in the system.
    existing_user = User.query.filter_by(username=form.username.data).first()
    existing_email = User.query.filter_by(email=form.email.data).first()

    #If the username is in use alert the user and rerender the register page.
    if existing_user:
        flash('Username already in use. Please choose a different one.', 'danger')
        return render_template('auth/register.html', form=form)
    #If the email is in use alert the user and rerender the register page.
    elif existing_email:
        flash('Email already in use. Please choose a different one.', 'danger')
        return render_template('auth/register.html', form=form)

    #Create a new User instance with the username from the form.
    new_user = User(username=form.username.data)
    new_user.hash_password = form.password.data
    new_user.email = form.email.data
    new_user.set_totp_secret()

    #Commit the new user to the database.
    db.session.add(new_user)
    db.session.commit()

    # Generate and send a confirmation email
    token = generate_confirmation_token(new_user.email)
    confirm_url = url_for('auth.confirm_email', token=token, _external=True)
    send_email(new_user.email, 'Confirm Your Account', 'auth/email_verification', confirm_url=confirm_url)

    #Redirect to the 2FA setup page.
    return redirect(url_for('auth.setup_2fa', user_id=new_user.id))


#Route to handle 2FA setup
@auth_bp.route('/setup_2fa', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def setup_2fa():
    #Nested function to generate QR code data for 2FA.
    def generate_qr_code(user):
        #Generates a TOTP URI used for creating the QR code.
        totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
            user.username, issuer_name='University of Agder message board')

        #Sets up the QR code generator with specific parameters.
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        #Adds the TOTP URI to the QR code.
        qr.add_data(totp_uri)
        #Generates the QR code.
        qr.make(fit=True)

        #Creates an image from the QR code.
        img = qr.make_image(fill_color="black", back_color="white")
        #Creates a BytesIO object to hold the image data.
        img_bytes = BytesIO()
        #Saves the image to the BytesIO object.
        img.save(img_bytes)
        #Resets the file pointer to the beginning.
        img_bytes.seek(0)
        #Encodes the image data to base64 for embedding in HTML.
        return base64.b64encode(img_bytes.getvalue()).decode('utf-8')

    #Retrieves the 'user_id' from the request arguments.
    user_id = request.args.get('user_id')
    #If no user is found notify the user and redirect back to register.
    if not user_id:
        flash('No registration in progress.', 'danger')
        return redirect(url_for('auth.register'))

    #Gets the user from the user id.
    new_user = User.query.get(user_id)
    #If the user does not exist or the user already has 2FA set up, notify the user and redirect to either index or register.
    if new_user is None or new_user.is_2fa_setup:
        flash('Invalid request or 2FA is already set up.', 'danger')
        return redirect(url_for('main.index' if new_user else 'auth.register'))

    #Get the TOTP form.
    form = TOTPForm()
    #Validate the form on post request.
    if form.validate_on_submit():
        #Create the TOTP object with the user's secret.
        totp = pyotp.TOTP(new_user.totp_secret)

        #If the submitted TOTP code is not valid notify the user and return to setup_2fa.html.
        if not totp.verify(form.totp_code.data):
            flash('Invalid 2FA code, please try again.', 'danger')
            return render_template('auth/setup_2fa.html', form=form, qr_code_data=generate_qr_code(new_user))

        #Mark 2FA as set up for the user.
        new_user.is_2fa_setup = True
        #Commit the changes to the database.
        db.session.commit()

        #Clear the existing session.
        session.clear()
        #Store the user's id in the session.
        session['user_id'] = new_user.id
        #Flag the session as modified.
        session.modified = True
        #Log the new user in.
        login_user(new_user)

        #Redirect to the homepage.
        return redirect(url_for('main.index'))

    #Prepare secret if not already set
    if not new_user.totp_secret:
        new_user.totp_secret = pyotp.random_base32()
        db.session.commit()

    #Render the page for GET requests or invalid POST submissions
    qr_code_data = generate_qr_code(new_user)
    return render_template('auth/setup_2fa.html', form=form, qr_code_data=qr_code_data)


#Route to handle logins
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    form = LoginForm()

    #Ensures logged in users cant access the login page.
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    #If the form is not submitted or not valid, just render the login page.
    if not form.validate_on_submit():
        return render_template('auth/login.html', form=form)

    #Query the database for a user with the given username.
    user = User.query.filter_by(username=form.username.data).first()

    #If the user is not found, flash a message.
    if not user:
        flash('Invalid username or password.', 'danger')
        return render_template('auth/login.html', form=form)

    #Check if the user's account is locked.
    locked, lock_until = user.is_account_locked()
    if locked:
        flash(f'Account is locked until {format_datetime(lock_until)}. Please try again later.', 'danger')
        return render_template('auth/login.html', form=form)

    #If the password is incorrect, flash a message and increment the user's failed attempts.
    if not user.verify_password(form.password.data):
        user.increment_failed_attempts()
        flash('Invalid username or password.', 'danger')
        return render_template('auth/login.html', form=form)

    #If 2FA is set up, start the 2FA verification process.
    if user.is_2fa_setup:
        session['verify_2fa'] = True
        session['username'] = user.username
        return redirect(url_for('auth.verify_2fa'))

    #If 2FA is not set up, redirect to 2FA setup.
    return redirect(url_for('auth.setup_2fa', user_id=user.id))


#Route to handle 2FA verification
@auth_bp.route('/verify_2fa', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def verify_2fa():
    #Ensure 'verify_2fa' and 'username' are in the session
    if 'verify_2fa' not in session or 'username' not in session:
        flash('Please login to verify 2FA.', 'warning')
        return redirect(url_for('auth.login'))

    #Get the TOTP form.
    form = TOTPForm()

    #Get the user from the database.
    user = User.query.filter_by(username=session.get('username')).first()

    #If the user is not found, clear the session and redirect to the login page.
    if not user:
        session.clear()
        flash('Session expired, please login again.', 'warning')
        return redirect(url_for('auth.login'))

    #If the form is not submitted or invalid, pop the session render the page again.
    if not form.validate_on_submit():
        session.pop('staged_user_data', None)
        return render_template('auth/verify_2fa.html', form=form)

    #Check the TOTP code, if it is invalid notify the user and pop the session.
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(form.totp_code.data):
        flash('Invalid 2FA code.', 'danger')
        session.pop('staged_user_data', None)
        return render_template('auth/verify_2fa.html', form=form)

    #Reset the user's failed login attempts.
    user.reset_failed_attempts()

    # Manually regenerate the session to prevent fixation.
    session.clear()  # Clear the existing session first.
    session['user_id'] = user.id  # Store the user id in the session.
    session['_id'] = uuid4().hex  # Generate a new session identifier.
    session.modified = True  # Mark the session as modified to force a save.

    #Log the user in.
    login_user(user)
    #Redirect to the home page.
    return redirect(url_for('main.index'))

#Route to handle logouts
@auth_bp.route('/logout')
@login_required
def logout():
    #Logs the user out.
    logout_user()
    #Clears the session.
    session.clear()
    #Redirects to the home page.
    return redirect(url_for('main.index'))

#Route to handle forgotten password. (FUTURE WORK)
@auth_bp.route('/forgotten_password', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def forgotten_password():
    pass

#Route to handle email verification.
@auth_bp.route('/confirm/<token>')
def confirm_email(token):
    #Confirm the confirmation token.
    email = confirm_token(token)
    #If not confirmed print the reason and redirect them to the login page.
    if not email:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.login'))

    #Query the user from the database.
    user = User.query.filter_by(email=email).first_or_404()

    #If the user is already confirmed inform the user.
    if user.email_confirmed:
        flash('Account already confirmed. Please login.', 'success')
    #If the user in not confirmed, set their email_confirmed field to true and inform the user.
    else:
        user.email_confirmed = True
        db.session.commit()
        flash('Your email has been confirmed. Please set up 2FA.', 'success')
        return redirect(url_for('auth.setup_2fa', user_id=user.id))

    return redirect(url_for('auth.login'))
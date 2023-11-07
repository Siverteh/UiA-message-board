from flask import render_template, request, redirect, url_for, flash, jsonify, abort, session, send_file
from models import db
from models import User, Message, Comment
from forms import RegistrationForm, LoginForm, MessageForm, CommentForm, TOTPForm
from flask_login import login_user, login_required, logout_user, current_user
from app import app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pytz
import pyotp
import qrcode
from io import BytesIO
import base64
from uuid import uuid4

#Set up a limiter to limit the number of requests per user.
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

#Global variable for the local timezone.
LOCAL_TIMEZONE = pytz.timezone('Europe/Oslo')

#Function to turn the datetime to the local timezone and format it.
def format_datetime(dt):
    if dt is None:
        return None
    # Convert the datetime object to the local timezone
    local_dt = dt.replace(tzinfo=pytz.utc).astimezone(LOCAL_TIMEZONE)
    return local_dt.strftime('%H:%M:%S')

#Route for the CSP header
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

#Route for the home page.
@app.route('/')
def index():
    #Query the database for all messages and order them by date posted.
    messages = Message.query.order_by(Message.date_posted.desc()).all()
    message_comments = {}

    #Organize comments for each message by their posted date in descending order, limited to 3 comments per message.
    for message in messages:
        message_comments[message.id] = Comment.query.filter_by(message_id=message.id).order_by(Comment.date_posted.desc()).limit(3).all()

    #Render the index page with the messages and their comments.
    return render_template('index.html', messages=messages, message_comments=message_comments)

#Function and route for viewing a single message.
@app.route('/message/<int:id>', methods=['GET', 'POST'])
def message(id):
    #Fetch a specific message by its id or return 404 if not found.
    message = Message.query.get_or_404(id)
    #Create an instance of the comment form.
    form = CommentForm()
    #If the form is submitted and the data is valid, create and save a new comment.
    if form.validate_on_submit():
        comment = Comment(
            content=form.content.data,
            message_id=message.id,
            author_id=current_user.id #Use the id of the currently logged-in user.
        )
        db.session.add(comment)
        db.session.commit()
        #Redirect to the same message page to display the new comment.
        return redirect(url_for('message', id=message.id))
    #Query for all comments belonging to a message, ordered by date posted in descending order.
    comments = Comment.query.filter_by(message_id=id).order_by(Comment.date_posted.desc()).all()

    #Render the message page with the message, comment form, and comments.
    return render_template('message.html', message=message, form=form, comments=comments)

#Route for adding a new message.
@app.route('/add', methods=['POST'])
def add():
    title = request.form['title']
    content = request.form['content']
    message = Message(title=title, content=content)
    db.session.add(message)
    db.session.commit()
    return redirect(url_for('index'))

#Route for creating a message.
@app.route('/create_message', methods=['GET', 'POST'])
@login_required
def create_message():
    #if the request method is POST, create a new message and save it to the database.
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        if not title or not content:
            flash('Title and Content are required!', 'danger')
            return redirect(request.url)
        message = Message(title=title, content=content, author=current_user)
        db.session.add(message)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('create_message.html')

#Route to edit a message.
@app.route('/edit_message/<int:message_id>', methods=['GET', 'POST'])
@login_required
def edit_message(message_id):
    #Fetch the message by its id or return 404 if not found.
    message = Message.query.get_or_404(message_id)
    #If the current user is not the same as the message author, return 403 Forbidden.
    if message.author != current_user:
        abort(403)
    form = MessageForm()
    #If the form is submitted and the data is valid, update the message and save it to the database.
    if form.validate_on_submit():
        message.title = form.title.data
        message.content = form.content.data
        db.session.commit()
        return redirect(url_for('message', id=message.id))
    form.title.data = message.title
    form.content.data = message.content
    return render_template('edit_message.html', form=form, message=message)

#Route to delete a message.
@app.route('/message/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    #Fetch the message by its id or return 404 if not found.
    message = Message.query.get_or_404(message_id)
    #If the current user is not the same as the message author, return 403 Forbidden.
    if current_user.id != message.author_id:
        abort(403)
    #Delete all comments belonging to the message then the message itself.
    Comment.query.filter_by(message_id=message_id).delete()
    db.session.delete(message)
    db.session.commit()
    return jsonify(status="success"), 200

#Route to delete a comment.
@app.route('/comment/delete/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    #Fetch the comment by its id or return 404 if not found.
    comment = Comment.query.get_or_404(comment_id)
    #If the current user is not the same as the comment author, return 403 Forbidden.
    if current_user.id != comment.author_id:
        abort(403)
    #Delete the comment from the database.
    db.session.delete(comment)
    db.session.commit()
    return jsonify(status="success"), 200

#Route to render comments.
@app.route('/comments/<int:id>')
def comments(id):
    # Your logic for displaying comments for the article with the given id.
    return render_template('comments.html', comments=comments)

#Route to handle registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    #Get the registration form
    form = RegistrationForm()

    #If the form is submitted and the data is valid
    if form.validate_on_submit():

        #Check if a user with the given username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()

        #If a user with the given username already exists
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', form=form)

        #Create a new User instance with the username from the form.
        new_user = User(username=form.username.data)
        new_user.hash_password = form.password.data
        new_user.set_totp_secret()

        db.session.add(new_user)
        db.session.commit()

        #Redirect to the 2FA setup page.
        return redirect(url_for('setup_2fa', user_id=new_user.id))

    #Render the registration page.
    return render_template('register.html', form=form)

#Route to handle 2FA setup
@app.route('/setup_2fa', methods=['GET', 'POST'])
def setup_2fa():
    user_id = request.args.get('user_id')
    if not user_id:
        flash('No registration in progress.', 'danger')
        return redirect(url_for('register'))

    new_user = User.query.get(user_id)
    if new_user.is_2fa_setup:
        flash('2FA is already set up for this user.', 'danger')
        return redirect(url_for('index'))

    #Get the TOTP form
    form = TOTPForm()

    #If the form is submitted and the data is valid
    if form.validate_on_submit():

        #Create a TOTP object with the user's secret.
        totp = pyotp.TOTP(new_user.totp_secret)

        #If the TOTP code is valid.
        if totp.verify(form.totp_code.data):

            new_user.is_2fa_setup = True
            db.session.commit()

            #Manually regenerate the session to prevent fixation.
            session.clear() #Clear the existing session first.
            session['user_id'] = new_user.id #Store the user id in the session.
            session.modified = True #Mark the session as modified to force a save.

            # Log the user in.
            login_user(new_user)

            #Redirect to the home page
            return redirect(url_for('index'))

        #If the TOTP code is invalid.
        else:
            flash('Invalid 2FA code, please try again.', 'danger')

        # Prepare for the first-time or re-display of the 2FA setup page
        if not new_user.totp_secret:
            new_user.totp_secret = pyotp.random_base32()
            db.session.commit()

    #Generate a provisioning URI which is needed for the QR Code
    totp_uri = pyotp.totp.TOTP(new_user.totp_secret).provisioning_uri(
        new_user.username, issuer_name='University of Agder message board')

    #Create the QR Code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    img_bytes = BytesIO()
    img.save(img_bytes)
    img_bytes.seek(0)

    #Encode the QR Code as base64 and decode it to a string.
    img_data = base64.b64encode(img_bytes.getvalue()).decode('utf-8')

    #Render the 2FA setup page.
    return render_template('setup_2fa.html', form=form, qr_code_data=img_data)

#Route to handle error 429 (too many requests).
@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('429.html'), 429

#Route to handle logins
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    #Get the login form.
    form = LoginForm()

    #If the form is submitted and the data is valid.
    if form.validate_on_submit():
        #Query the database for a user with the given username.
        user = User.query.filter_by(username=form.username.data).first()
        #If the user is found.
        if user:
            #Check if the user's account is locked and if so how long.
            locked, lock_until = user.is_account_locked()
            #If the account is locked.
            if locked:
                #Flash how long the account is locked for and redirect to the login page.
                flash(f'Account is locked until {format_datetime(lock_until)}. Please try again later.', 'danger')
                return render_template('login.html', form=form)

            #If the password is correct.
            if user.verify_password(form.password.data):
                if user.is_2fa_setup == True:
                    #Start the 2fa verification process.
                    session['verify_2fa'] = True
                    session['username'] = user.username
                    return redirect(url_for('verify_2fa'))
                else:
                    return redirect(url_for('setup_2fa', user_id=user.id))

            #If the password is incorrect.
            else:
                #Flash a message and increment the user's failed attempts.
                user.increment_failed_attempts()
                flash('Invalid username or password.', 'danger')

        #If the user is not found.
        else:
            #Flash a message.
            flash('Invalid username or password.', 'danger')

    #Render the login page.
    return render_template('login.html', form=form)

#Route to handle 2FA verification
@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    #Require that 'verify_2fa' is in the session to access this page
    if 'verify_2fa' not in session or 'username' not in session:
        flash('Please login to verify 2FA.', 'warning')
        return redirect(url_for('login'))

    #Get the TOTP form.
    form = TOTPForm()
    #Get the user from the database.
    user = User.query.filter_by(username=session.get('username')).first()

    #If the user is not found, clear the session and redirect to the login page.
    if not user:
        session.clear()
        flash('Session expired, please login again.', 'warning')
        return redirect(url_for('login'))

    #If the form is submitted and the data is valid.
    if form.validate_on_submit():
        #Create a TOTP object with the user's secret.
        totp = pyotp.TOTP(user.totp_secret)
        #If the TOTP code is valid.
        if totp.verify(form.totp_code.data):
            #Reset the user's failed attempts.
            user.reset_failed_attempts()

            # Manually regenerate the session to prevent fixation.
            session.clear()  # Clear the existing session first.
            session['user_id'] = user.id  # Store the user id in the session.
            session['_id'] = uuid4().hex  # Generate a new session identifier.
            session.modified = True  # Mark the session as modified to force a save.

            #Log the user in.
            login_user(user)
            #Redirect to the home page.
            return redirect(url_for('index'))

        #If not the form is either not submitted or not valid.
        else:
            flash('Invalid 2FA code.', 'danger')
            session.pop('staged_user_data', None)
    else:
        session.pop('staged_user_data', None)

    #Render the 2FA verification page.
    return render_template('verify_2fa.html', form=form)

#Route to handle logouts
@app.route('/logout')
@login_required
def logout():
    #Logs the user out.
    logout_user()
    #Clears the session.
    session.clear()
    #Redirects to the home page.
    return redirect(url_for('index'))


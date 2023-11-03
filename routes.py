from flask import render_template, request, redirect, url_for, flash, jsonify, abort
from models import db
from models import User, Message, Comment
from forms import RegistrationForm, LoginForm, MessageForm, CommentForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from app import app


@app.after_request
def apply_csp(response):
    # Generate a random nonce value for the CSP policy
    import secrets
    nonce = secrets.token_hex(16)  # Generate a random 16-character nonce

    # This policy allows scripts and styles from the same origin
    # and blocks all object sources, except for 'trusted_scripts.js' using the nonce.
    csp_policy = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self'; "  # Allow styles from the same origin
        "object-src 'none';"
    )

    response.headers['Content-Security-Policy'] = csp_policy
    return response

@app.route('/')
def index():
    messages = Message.query.order_by(Message.date_posted.desc()).all()
    message_comments = {}
    for message in messages:
        message_comments[message.id] = Comment.query.filter_by(message_id=message.id).order_by(Comment.date_posted.desc()).limit(3).all()
    return render_template('index.html', messages=messages, message_comments=message_comments)

@app.route('/message/<int:id>', methods=['GET', 'POST'])
def message(id):
    message = Message.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(
            content=form.content.data,
            message_id=message.id,
            author_id=current_user.id
        )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('message', id=message.id))
    comments = Comment.query.filter_by(message_id=id).order_by(Comment.date_posted.desc()).all()
    return render_template('message.html', message=message, form=form, comments=comments)

@app.route('/add', methods=['POST'])
def add():
    title = request.form['title']
    content = request.form['content']
    message = Message(title=title, content=content)
    db.session.add(message)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/create_message', methods=['GET', 'POST'])
@login_required
def create_message():
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

@app.route('/edit_message/<int:message_id>', methods=['GET', 'POST'])
@login_required
def edit_message(message_id):
    message = Message.query.get_or_404(message_id)
    if message.author != current_user:
        abort(403)
    form = MessageForm()
    if form.validate_on_submit():
        message.title = form.title.data
        message.content = form.content.data
        db.session.commit()
        return redirect(url_for('message', id=message.id))
    form.title.data = message.title
    form.content.data = message.content
    return render_template('edit_message.html', form=form, message=message)

@app.route('/message/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    if current_user.id != message.author_id:
        abort(403)
    Comment.query.filter_by(message_id=message_id).delete()
    db.session.delete(message)
    db.session.commit()
    return jsonify(status="success"), 200

@app.route('/comment/delete/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if current_user.id != comment.author_id:
        abort(403)
    db.session.delete(comment)
    db.session.commit()
    return jsonify(status="success"), 200

@app.route('/comments/<int:id>')
def comments(id):
    # Your logic for displaying comments for the article with the given id.
    return render_template('comments.html', comments=comments)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

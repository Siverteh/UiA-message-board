from flask import render_template, request, redirect, url_for, flash, jsonify, abort, Blueprint
from models import db
from models import Message, Comment
from forms import MessageForm, CommentForm, TOTPForm
from flask_login import login_required, current_user

message_bp = Blueprint('message', __name__)


#Function and route for viewing a single message.
@message_bp.route('/message/<int:id>', methods=['GET', 'POST'])
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
        return redirect(url_for('message.message', id=message.id))
    #Query for all comments belonging to a message, ordered by date posted in descending order.
    comments = Comment.query.filter_by(message_id=id).order_by(Comment.date_posted.desc()).all()

    #Render the message page with the message, comment form, and comments.
    return render_template('messages/message.html', message=message, form=form, comments=comments)

#Route for creating a message.
@message_bp.route('/create_message', methods=['GET', 'POST'])
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
        return redirect(url_for('main.index'))
    return render_template('messages/create_message.html')

#Route to edit a message.
@message_bp.route('/edit_message/<int:message_id>', methods=['GET', 'POST'])
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
        return redirect(url_for('message.message', id=message.id))
    form.title.data = message.title
    form.content.data = message.content
    return render_template('messages/edit_message.html', form=form, message=message)

#Route to delete a message.
@message_bp.route('/message/delete/<int:message_id>', methods=['POST'])
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
@message_bp.route('/comment/delete/<int:comment_id>', methods=['POST'])
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
@message_bp.route('/comments/<int:id>')
def comments(id):
    # Your logic for displaying comments for the article with the given id.
    return render_template('comments.html', comments=comments)

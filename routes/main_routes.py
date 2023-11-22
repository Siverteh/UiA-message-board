from flask import Blueprint, render_template
from models import Message, Comment

main_bp = Blueprint('main', __name__)

#Route for the home page.
@main_bp.route('/')
def index():
    #Query the database for all messages and order them by date posted.
    messages = Message.query.order_by(Message.date_posted.desc()).all()
    message_comments = {}

    #Organize comments for each message by their posted date in descending order, limited to 3 comments per message.
    for message in messages:
        message_comments[message.id] = Comment.query.filter_by(message_id=message.id).order_by(Comment.date_posted.desc()).limit(3).all()

    #Render the index page with the messages and their comments.
    return render_template('index.html', messages=messages, message_comments=message_comments)
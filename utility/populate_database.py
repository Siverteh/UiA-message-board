from models import User, Message, Comment
from utility.extensions import db
from werkzeug.security import generate_password_hash

def create_user(username, email, password):
    user = User(username=username, email=email)
    user.password_hash = generate_password_hash(password)
    return user

def create_message(author_id, title, content):
    message = Message(title=title, content=content, author_id=author_id)
    return message

def create_comment(author_id, message_id, content):
    comment = Comment(content=content, author_id=author_id, message_id=message_id)
    return comment

def populate_database():
    # Create users
    users = [
        create_user("alice", "alice@uia.no", "alice123"),
        create_user("bob", "bob@uia.no", "bob123"),
        create_user("charlie", "charlie@uia.no", "charlie123")
    ]

    for user in users:
        db.session.add(user)
    db.session.commit()

    # Create messages
    messages = [
        create_message(users[0].id, "Welcome to UiA", "Hello everyone! Welcome to the University of Agder message board. This platform is for all UiA students and staff to share news, events, and discussions."),
        create_message(users[1].id, "Study Group", "Hey folks, I'm organizing a study group for the upcoming exam in Software Security. Anyone interested in joining?"),
        create_message(users[2].id, "Campus Event", "Reminder: There's a campus event this Friday at the main auditorium. Guest speakers, workshops, and networking opportunities. Don't miss out!")
    ]

    for message in messages:
        db.session.add(message)
    db.session.commit()

    # Create specific comments for each message
    comments_welcome = [
        create_comment(users[1].id, messages[0].id, "Excited to be part of this community!"),
        create_comment(users[2].id, messages[0].id, "Looking forward to engaging discussions here."),
        create_comment(users[0].id, messages[0].id, "Feel free to share your thoughts and ideas!")
    ]

    comments_study_group = [
        create_comment(users[0].id, messages[1].id, "I'm in! Need all the help I can get."),
        create_comment(users[2].id, messages[1].id, "Is this open for beginners too?"),
        create_comment(users[1].id, messages[1].id, "Sure thing! The more, the merrier.")
    ]

    comments_campus_event = [
        create_comment(users[0].id, messages[2].id, "Can't wait for the networking session."),
        create_comment(users[1].id, messages[2].id, "I heard there will be some interesting workshops."),
        create_comment(users[2].id, messages[2].id, "Definitely attending. Thanks for the info!")
    ]

    all_comments = comments_welcome + comments_study_group + comments_campus_event

    for comment in all_comments:
        db.session.add(comment)
    db.session.commit()

    print("Database populated with UiA-related data.")

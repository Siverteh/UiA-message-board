from datetime import datetime, timedelta
from extensions import db, login_manager, bcrypt
from flask_login import UserMixin
import pyotp

#User model contains username, password hash, and messages fields.
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, index=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)
    lock_until = db.Column(db.DateTime, default=None)
    totp_secret = db.Column(db.String(16))
    is_2fa_setup = db.Column(db.Boolean, default=False)
    messages = db.relationship('Message', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

    #Sets the passowrd attribute as a write-only property
    @property
    def hash_password(self):
        raise AttributeError('Password is not a readable attribute.')

    #Hashes password and sets password_hash attribute
    @hash_password.setter
    def hash_password(self, password_plaintext):
        self.password_hash = bcrypt.generate_password_hash(password_plaintext).decode('utf-8')

    #Checks if password is correct by comparing hashes
    def verify_password(self, password_plaintext):
        return bcrypt.check_password_hash(self.password_hash, password_plaintext)

    #Increments failed attempts and locks account if failed attempts is greater than or equal to 3
    def increment_failed_attempts(self):
        self.failed_attempts += 1
        if self.failed_attempts >= 3:
            self.lock_until = datetime.utcnow() + timedelta(minutes=30)
        db.session.commit()

    #Checks if account is locked, and for how long.
    def is_account_locked(self):
        if self.lock_until and datetime.utcnow() < self.lock_until:
            return True, self.lock_until
        return False, None

    #Resets failed attempts and lock_until attributes
    def reset_failed_attempts(self):
        self.failed_attempts = 0
        self.lock_until = None
        db.session.commit()

    #Sets TOTP secret for user.
    def set_totp_secret(self):
        self.totp_secret = pyotp.random_base32()



#Returns user object from user ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Message model contains title, content, date posted, and author ID fields.
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='message', lazy=True, cascade="all, delete-orphan")

#Comment model contains content, date posted, message ID, and author ID fields.
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

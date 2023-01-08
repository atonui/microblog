'''this script models the database at a high level using classes'''
from datetime import datetime
from hashlib import md5
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import db, login

@login.user_loader #user loader that can be called by flask-login to load a user given the id
def load_user(userid):
    return User.query.get(int(userid))

class User(UserMixin, db.Model):
    '''class to model the user in the database'''
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(64), index = True, unique = True)
    email = db.Column(db.String(120), index = True, unique = True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        '''function to hash passwords'''
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        '''function to check hashed password and return a true or false'''
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        '''user avatar generator (instead of letting users upload their images'''
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https:www.gravatar.com/avatar/{}?d=identicons&s={}'.format(digest, size)

class Post(db.Model):
    '''class to model posts in the database'''
    id = db.Column(db.Integer, primary_key = True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Post {}>'.format(self.body)

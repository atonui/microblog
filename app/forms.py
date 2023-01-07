'''this script handles the various web forms in this app'''
from flask_wtf import FlaskForm
from flask import Flask
from wtforms import StringField, PasswordField, BooleanField, SubmitField
#from wtforms.validators import DataRequired
from wtforms import validators
from app.models import User

class LoginForm(FlaskForm):
    '''this class creates the user log in form fields'''
    username = StringField('Username', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    '''this class creates the user registration form'''
    username = StringField('Username', validators=[validators.DataRequired()])
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[validators.DataRequired(), validators.EqualTo('password')]
        )
    submit = SubmitField('Register')

    def validate_username(self, username):
        '''this function validates the registered username'''
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise validators.ValidationError('Please use a different email username.')

    def validate_email(self, email):
        '''this function validates the registered email'''
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise validators.ValidationError('Please use a different email address.')

'''this script handles the various web forms in this app'''
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
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
            raise validators.ValidationError('Please use a different username.')

    def validate_email(self, email):
        '''this function validates the registered email'''
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise validators.ValidationError('Please use a different email address.')

class EditProfileForm(FlaskForm):
    '''class to create the profile edit form'''
    username = StringField('Username', validators=[validators.DataRequired()])
    about_me = TextAreaField('About me', validators=[validators.Length(min=0, max=140)])
    submit = SubmitField('Submit')
     
    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise validators.ValidationError('Please use a different username.')
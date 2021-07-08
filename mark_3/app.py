from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired
from flask_bcrypt import Bcrypt

##############################################################################

# creating the app, database, setting the secret key and hashing the password
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

###################Database and form validation#########################

# function to load a user from the database


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Class to make the column in the database


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

# class to take in the registration info


class SignupForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=30)], render_kw={"placeholder:Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField("Signup")

    # function to validate username
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists please choose a different one")

    # function to validate password
    def validate_password(self, password, confirm_password):
        if password.data != confirm_password.data:
            raise ValidationError(
                "The entered password does not match the the confirmed password")


# Class to take in the login info
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=30)], render_kw={"placeholder:Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


######################The functions following are routes#######################

# route for the home page
@app.route('/')
def home():
    return render_template('home.html')

# route for the login page


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

# route for the dashboard


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

# route for the logout page


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    return redirect(url_for('login'))

# route for the sign up page


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


#import guard
if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, render_template, request, flash, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__, static_folder='assets')
app.config.from_pyfile('./config.py')

# app.config['SECRET_KEY'] = 'sectet'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqlite.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bootstrap = Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(15), unique=True)
	email = db.Column(db.String(50), unique=True)
	password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))	


class LoginForm(FlaskForm):
	username = StringField('username', validators=[InputRequired()])
	password = PasswordField('password', validators=[InputRequired()])
	remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
	email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	username = StringField('username', validators=[InputRequired(), Length(min=2, max=20)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=2, max=70)])	


@app.route('/')
def index():
	return render_template('index.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
	if current_user.is_active:
		return redirect(url_for('index'))  

	form = LoginForm()

	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()

		if user:
			if check_password_hash(user.password, form.password.data):
				login_user(user, remember=form.remember.data)

				return redirect(url_for('dashboard'))
		
		flash('Password or username is not correct', 'error')		

	return render_template('login.html', form=form)


@app.route('/signup', methods=['POST', 'GET'])
def signup():
	if current_user.is_active:
		return redirect(url_for('index')) 

	form = RegisterForm()

	if form.validate_on_submit():
		hashed_password = generate_password_hash(form.password.data, method='sha256')
		new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)

		db.session.add(new_user)
		db.session.commit()

		flash('Registration completed successfully. Come in, please.', 'success')

		return redirect(url_for('login'))

	return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
	return render_template('dashboard.html', name=current_user.username)		


@app.route('/logout')
@login_required
def logout():
	logout_user()

	return redirect(url_for('login'))


if __name__=='__main__':
	app.run()
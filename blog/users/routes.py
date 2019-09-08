from flask import Flask, render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

from flask_mail import Message
from threading import Thread
from itsdangerous import URLSafeTimedSerializer

from blog.users.forms import LoginForm, RegistrationForm, RequestResetForm, ResetPasswordForm
from blog.models import User
from blog import db, app, mail

users_bp = Blueprint('users_bp', __name__)

@users_bp.route('/register')
def register_user():
    form = RegistrationForm()
    
    return render_template('register.html', form = form)

@users_bp.route('/register', methods=['POST'])
def register_user_post():
    if current_user.is_authenticated:
        return redirect( url_for('dashboard_bp.dashboard') )

    form = RegistrationForm(request.form)
    if form.validate():
        hashed_password = generate_password_hash(form.password.data, method = 'pbkdf2:sha256')
        
        new_user = User(
            email = request.form.get('email').lower(),
            first_name = request.form.get('first_name').lower(),
            last_name = request.form.get('last_name').lower(),
            password = hashed_password
        )
        db.session.add(new_user)
        db.session.commit()

        send_confirmation_email(new_user.email)

        flash('The confirmation link is sent.')

        return redirect(url_for('users_bp.login'))

    for error in form.errors.items():
        flash(error[0].capitalize() + ': '+ str(error[1][0]))
        
    return redirect(url_for('users_bp.register_user'))

@users_bp.route('/')
@users_bp.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_bp.dashboard'))

    form = LoginForm()
    return render_template('login.html', form = form)

@users_bp.route('/', methods=['POST'])
@users_bp.route('/login', methods=['POST'])
def login_post():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_bp.dashboard'))

    form = LoginForm(request.form)

    user = User.query.filter_by(email = request.form.get('email').lower()).first()

    if user and form.validate() and check_password_hash(user.password, request.form.get('password')):
        login_user(user)
        return redirect(url_for('dashboard_bp.dashboard'))

    flash('You have entered an invalid username or password!')
    return redirect(url_for('users_bp.login'))

@users_bp.route('/logout')
@login_required
def logout():
    logout_user()

    return redirect(url_for('users_bp.login'))

@users_bp.route("/reset_password")
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_bp.dashboard'))

    return render_template('reset_request.html', form = RequestResetForm())

@users_bp.route("/reset_password", methods=['POST'])
def reset_request_post():
    form = RequestResetForm(request.form)

    user = User.query.filter_by(email = request.form.get('email')).first()

    if user and form.validate():
        send_reset_email(request.form.get('email').lower())
        flash('An email has been sent with instructions to reset your password.')
    else:
        flash('There is no account with that email. You must register first.')

    return redirect(url_for('users_bp.login'))

@users_bp.route('/reset/<token>')
def reset_with_token(token):
    form = ResetPasswordForm()

    return render_template('reset_password.html', form = form, token = token)

@users_bp.route('/reset/<token>', methods=['POST'])
def reset_with_token_post(token):
    try:
        password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = password_reset_serializer.loads(token, salt='password-reset-salt', max_age=1800)
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('users_bp.login'))

    form = ResetPasswordForm(request.form)
    
    if form.validate():
        user = User.query.filter_by(email = email).first()
        
        user.password = generate_password_hash(request.form.get('password'), method = 'pbkdf2:sha256')
        db.session.commit()
        
        flash('Your password has been updated!')
        return redirect(url_for('users_bp.login'))

    for error in form.errors.items():
        flash(error[0].capitalize() + ': '+ str(error[1][0]))

    return redirect(url_for('users_bp.reset_with_token', token = token))


@users_bp.route('/confirm/<token>')
def confirm_email(token):
    try:
        confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = confirm_serializer.loads(token, salt='email-confirmation-salt', max_age=1800)
    except:
        flash('The confirmation link is invalid or has expired.')
        return redirect(url_for('users_bp.login'))

    user = User.query.filter_by(email = email).first()

    if user.email_confirmed:
        flash('Account already confirmed. Please login.')
    else:
        user.email_confirmed = True
        user.email_confirmed_on = datetime.now()
        db.session.add(user)
        db.session.commit()
        
        flash('Thank you for confirming your email address!')

    return redirect(url_for('dashboard_bp.dashboard'))

def send_async_email(msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, recipients, html_body):
    msg = Message(subject, recipients=recipients)
    msg.html = html_body
    thr = Thread(target=send_async_email, args=[msg])
    thr.start()


def send_confirmation_email(user_email):
    confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    confirm_url = url_for(
        'users_bp.confirm_email',
        token=confirm_serializer.dumps(user_email, salt='email-confirmation-salt'), _external=True)

    html = render_template(
        'email_confirmation.html',
        confirm_url = confirm_url)

    send_email('Confirm Your Email Address', [user_email], html)

def send_reset_email(user_email):
    password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    password_reset_url = url_for(
        'users_bp.reset_with_token',
        token = password_reset_serializer.dumps(user_email, salt='password-reset-salt'), _external=True)

    html = render_template(
        'email_password_reset.html',
        password_reset_url = password_reset_url)

    send_email('Password Reset Requested', [user_email], html)


from flask import Flask, render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

from blog.users.forms import LoginForm, RegistrationForm
from blog.models import User
from blog import db

users_bp = Blueprint('users_bp', __name__)

@users_bp.route('/register')
def register_user():
    form = RegistrationForm()
    
    return render_template('register.html', form = form)

@users_bp.route('/register', methods=['POST'])
def register_user_post():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

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
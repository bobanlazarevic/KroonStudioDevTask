from sqlalchemy import and_
from datetime import datetime
from flask import Flask, request, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

from blog.models import User, Category, Article
from blog import app, db

import uuid
import re

# This is just for testing purposes
SUCCESS_MESSAGE = {
    'NewUser': { 'Success': 'New user created!', 'Code': 200 },
    'LoggedIn': { 'Success': 'Logged in', 'Code': 200 },
    'CategoryCreated': { 'Success': 'Successfully created a new category', 'Code': 200 },
    'ArticleCreated': { 'Success': 'Successfully created a new article', 'Code': 200 },
    'ArticleDeleted': { 'Success': 'Successfully deleted the article', 'Code': 200 },
    'LoggedOut': { 'Success': 'Successfully logged out', 'Code': 200 }
}

ERROR_MESSAGE = {
    'IncorrectEmail': { 'Error': 'That email address is already in use!', 'Code': 401 },
    'IncorrectPassword': { 'Error': 'Minimum length 8 characters, must contain at least one capitalized letter at least one number digit and at least one symbol!', 'Code': 401},
    'Unauthorized': { 'Error' : 'Incorrect password or email address entered. Please try again!', 'Code': 401 },
    'TokenMissing': { 'Error' : 'Token is missing!', 'Code': 401 },
    'TokenInvalid': { 'Error' : 'Token is invalid!', 'Code': 401 },
    'CategoryExists': { 'Error': 'Category already exists!', 'Code': 409 },
    'CategoryNotFound': { 'Error': 'Category not found!', 'Code': 404 },
    'TitleNotUnique': { 'Error': 'Article with this title already exists!', 'Code': 403 },
    'ArticleNotFound': { 'Error': 'Article not found!', 'Code': 404 },
    'DummyLogin': { 'Error': 'DummyLogin!', 'Code': 404 },
}

# This is just for testing purposes
@app.route('/dummy')
def dummy():
    return jsonify( ERROR_MESSAGE['DummyLogin'] )

@app.route('/register', methods = ['POST'])
def register_user():
    if current_user.is_active():
        pass

    data = request.get_json()

    user = User.query.filter_by(email = data['email']).first()
    if user:
        return jsonify( ERROR_MESSAGE['IncorrectEmail'] )

    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", data['password']):
        return jsonify( ERROR_MESSAGE['IncorrectPassword'] )

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')

    new_user = User(
        email = data['email'],
        first_name = data['first_name'],
        last_name = data['last_name'],
        password = hashed_password
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify( SUCCESS_MESSAGE['NewUser'] )

# This is just for testing purposes
@app.route('/login', methods=['POST'])
def login():
    if current_user and current_user.is_active():
        pass

    data = request.get_json()

    email = data['Username']
    password = data['Password']

    user = User.query.filter_by(email = email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify( ERROR_MESSAGE['Unauthorized'] )

    login_user(user)
    
    return jsonify( SUCCESS_MESSAGE['LoggedIn'] )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify( SUCCESS_MESSAGE['LoggedOut'] )

@app.route('/category', methods=['POST'])
@login_required
def add_category():
    data = request.get_json()

    category = Category.query.filter_by(title = data['title']).first()

    if category:
        return jsonify( ERROR_MESSAGE['CategoryExists'] )

    new_category = Category(title = data['title'])
    db.session.add(new_category)
    db.session.commit()

    return jsonify( SUCCESS_MESSAGE['CategoryCreated'] )

@app.route('/category', methods=['GET'])
@login_required
def get_all_categories():
    categories = Category.query.all()

    output = []

    for category in categories:
        category_data = {}
        category_data['title'] = category.title
        output.append(category_data)

    return jsonify({'Categories' : output})

@app.route('/article', methods=['POST'])
@login_required
def create_article():
    data = request.get_json()

    category = Category.query.filter_by(title = data['category']).first()
    if not category:
        return jsonify( ERROR_MESSAGE['CategoryNotFound'] )

    titles = Article.query.filter(and_(Article.category_id == category.id, Article.title == data['title'])).all()
    if titles:
        return jsonify( ERROR_MESSAGE['TitleNotUnique'] )

    new_article = Article(title = data['title'], content = data['content'], owner_id = current_user.id, category_id = category.id)
    db.session.add(new_article)
    db.session.commit()

    return jsonify( SUCCESS_MESSAGE['ArticleCreated'] )

@app.route('/article', methods=['GET'])
@login_required
def get_all_articles():
    articles = Article.query.all()

    output = []

    for article in articles:
        article_data = {}
        article_data['title'] = article.title
        article_data['content'] = article.content
        article_data['category'] = article.category.title
        article_data['first_name'] = article.owner.first_name
        article_data['last_name'] = article.owner.first_name
        article_data['created_at'] = article.created_at
        article_data['updated_at'] = article.updated_at
        output.append(article_data)

    return jsonify({'Articles' : output})

@app.route('/article/<article_id>', methods=['DELETE'])
@login_required
def delete_article(article_id):
    article = Article.query.filter_by(id = article_id, owner_id = current_user.id).first()

    if not article:
        return jsonify( ERROR_MESSAGE['ArticleNotFound'] )

    db.session.delete(article)
    db.session.commit()

    return jsonify( SUCCESS_MESSAGE['ArticleDeleted'] )

@app.route('/article/<article_id>', methods=['put'])
@login_required
def update_article(article_id):
    data = request.get_json()

    article = Article.query.filter_by(id = article_id, owner_id = current_user.id).first()

    if not article:
        return jsonify( error_message['articlenotfound'] )

    category = Category.query.filter_by(title = data['category']).first()
    if not category:
        return jsonify( error_message['categorynotfound'] )

    article.title = data['title']
    article.content = data['content']
    article.category_id = category.id;
    article.updated_at = datetime.now()

    db.session.commit()

    return jsonify( SUCCESS_MESSAGE['articleupdated'] )

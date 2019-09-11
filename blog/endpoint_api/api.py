from flask import Blueprint, request, jsonify, make_response
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from blog.models import *
from blog import app, db

import jwt
import re

api_bp= Blueprint('api_bp', __name__)

SUCCESS_MESSAGE = {
    'NewUser': { 'Success': 'New user created!', 'Code': 200 },
    'LoggedIn': { 'Success': 'Logged in', 'Code': 200 },
    'CategoryCreated': { 'Success': 'Successfully created a new category', 'Code': 200 },
    'ArticleCreated': { 'Success': 'Successfully created a new article', 'Code': 200 },
    'ArticleDeleted': { 'Success': 'Successfully deleted the article', 'Code': 200 }
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
}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'error' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id = data['id']).first()
        except:
            return jsonify({'error' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@api_bp.route('/api/register', methods = ['POST'])
def register_user():
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

@app.route('/api/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify( ERROR_MESSAGE['Unauthorized'] )

    user = User.query.filter_by(email = auth.username).first()

    if not user:
        return jsonify( ERROR_MESSAGE['Unauthorized'] )

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'id' : user.id, 'exp' : datetime.now() - timedelta(hours = 2) + timedelta(minutes = 30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return jsonify( ERROR_MESSAGE['Unauthorized'] )

@app.route('/api/category', methods=['POST'])
@token_required
def add_category(current_user):
    data = request.get_json()

    category = Category.query.filter_by(title = data['title']).first()

    if category:
        return jsonify( ERROR_MESSAGE['CategoryExists'] )

    new_category = Category(title = data['title'])
    db.session.add(new_category)
    db.session.commit()

    return jsonify( SUCCESS_MESSAGE['CategoryCreated'] )

@app.route('/api/category', methods=['GET'])
@token_required
def get_all_categories(current_user):
    categories = Category.query.all()

    output = []

    for category in categories:
        category_data = {}
        category_data['title'] = category.title
        output.append(category_data)

    return jsonify({'Categories' : output})

@app.route('/api/article', methods=['POST'])
@token_required
def create_article(current_user):
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

@app.route('/api/article', methods=['GET'])
@token_required
def get_all_articles(current_user):
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

@app.route('/api/article/<article_id>', methods=['DELETE'])
@token_required
def delete_article(current_user, article_id):
    article = Article.query.filter_by(id = article_id, owner_id = current_user.id).first()

    if not article:
        return jsonify( ERROR_MESSAGE['ArticleNotFound'] )

    db.session.delete(article)
    db.session.commit()

    return jsonify( SUCCESS_MESSAGE['ArticleDeleted'] )

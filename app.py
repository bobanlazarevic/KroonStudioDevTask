from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from sqlalchemy import and_

import uuid
import re
import jwt

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SamoZaTvojeOci'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

db = SQLAlchemy(app)

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

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    public_id = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now())

    articles = db.relationship('Article', backref='owner')

    def __repr__(self):
        return f"User('{self.first_name}', '{self.last_name}', '{self.email}')"

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), unique=True, nullable=False)

    categories = db.relationship('Article', backref='category')

    def __repr__(self):
        return f"Category('{self.title}')"

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50), nullable=False) # unique=True
    content = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now())
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.now())

    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

    def __repr__(self):
        return f"Article('{self.title}', '{self.content}')"

def jwt_token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return ERROR_MESSAGE['TokenMissing']

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id = data['public_id']).first()
        except:
            return ERROR_MESSAGE['TokenInvalid']

        return func(current_user, *args, **kwargs)

    return decorated

@app.route('/register', methods = ['POST'])
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
        public_id = str(uuid.uuid4()),
        first_name = data['first_name'],
        last_name = data['last_name'],
        password = hashed_password
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify( SUCCESS_MESSAGE['NewUser'] )

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify( ERROR_MESSAGE['Unauthorized'] )

    user = User.query.filter_by(email = auth.username).first()

    if not user:
        return jsonify( ERROR_MESSAGE['Unauthorized'] )

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.now() + timedelta(minutes = 30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return jsonify( ERROR_MESSAGE['Unauthorized'] )

@app.route('/category', methods=['POST'])
@jwt_token_required
def add_category(current_user):
    data = request.get_json()

    category = Category.query.filter_by(title = data['title']).first()

    if category:
        return jsonify( ERROR_MESSAGE['CategoryExists'] )

    new_category = Category(title = data['title'])
    db.session.add(new_category)
    db.session.commit()

    return jsonify( SUCCESS_MESSAGE['CategoryCreated'] )

@app.route('/category', methods=['GET'])
@jwt_token_required
def get_all_categories(current_user):
    categories = Category.query.all()

    output = []

    for category in categories:
        category_data = {}
        category_data['title'] = category.title
        output.append(category_data)

    return jsonify({'Categories' : output})

@app.route('/article', methods=['POST'])
@jwt_token_required
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

@app.route('/article', methods=['GET'])
@jwt_token_required
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

@app.route('/article/<article_id>', methods=['DELETE'])
@jwt_token_required
def delete_article(current_user, article_id):
    article = Article.query.filter_by(id = article_id, owner_id = current_user.id).first()

    if not article:
        return jsonify( ERROR_MESSAGE['ArticleNotFound'] )

    db.session.delete(article)
    db.session.commit()

    return jsonify( SUCCESS_MESSAGE['ArticleDeleted'] )

if __name__ == '__main__':
    app.run(debug=True)

    #import os
    #HOST = os.environ.get('SERVER_HOST', 'localhost')
    #try:
    #    PORT = int(os.environ.get('SERVER_PORT', '5555'))
    #except ValueError:
    #    PORT = 5555
    #app.run(HOST, PORT)

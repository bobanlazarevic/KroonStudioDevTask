from sqlalchemy import and_
from datetime import datetime
from flask import Flask, render_template, url_for, flash, redirect, request, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

from blog.forms import LoginForm, RegistrationForm, CreateArticleForm, CreateCategoryForm
from blog.models import User, Category, Article
from blog import app, db

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            hashed_password = generate_password_hash(form.password.data, method = 'pbkdf2:sha256')
        
            new_user = User(
                email = form.email.data,
                first_name = form.first_name.data,
                last_name = form.last_name.data,
                password = hashed_password
            )
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login'))
        else:
            return redirect(url_for('register_user')) 

    return render_template('register.html', title = 'Sign up', form = form)

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()

    if request.method == 'POST':
        user = User.query.filter_by(email = form.email.data).first()
        if user: # form.validate() and user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('login')) 

    return render_template('login.html', title = 'Login', form = form)

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/category', methods=['GET', 'POST'])
@login_required
def add_category():

    form = CreateCategoryForm()

    if request.method == 'POST':
        category = Category.query.filter_by(title = form.title.data).first()
        if not category and form.validate_on_submit():
            new_category = Category(title = form.title.data)
            db.session.add(new_category)
            db.session.commit()
            
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('add_category')) 

    return render_template('createcategory.html', title = 'Add category', form = form)

@app.route('/createarticle', methods=['GET', 'POST'])
@login_required
def create_article():

    form = CreateArticleForm()

    form.categories.choices = [(c.id, c.title) for c in Category.query.order_by(Category.id.asc()).all()]

    if request.method == 'POST':
        index = int( form.categories.data )
        category_id = form.categories.choices[index - 1][0]

        titles = Article.query.filter(and_(Article.category_id == category_id, Article.title == str(form.title.data))).first()

        if not titles and form.validate_on_submit():
            new_article = Article(title = str(form.title.data), content = str(form.content.data), owner_id = current_user.id, category_id = category_id)
            db.session.add(new_article)
            db.session.commit()
            
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('create_article'))

    return render_template('createarticle.html', title = 'Create article', form = form)

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

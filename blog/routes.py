from sqlalchemy import and_
from datetime import datetime
from flask import Flask, render_template, url_for, flash, redirect, request, session, jsonify
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
            session['active_user'] = user.first_name + ' ' + user.last_name
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('login')) 

    return render_template('login.html', title = 'Login', form = form)

@app.route('/search', methods=['GET'])
def search():
    keyword = request.args.get('query')
    results = Article.query.msearch(keyword, fields=['title', 'content'], limit=10)

    return render_template('dashboard.html', search_results = results)

@app.route('/single/<int:article_id>')
def single_article(article_id):
    article = Article.query.get_or_404(article_id)

    article_data = {}
    article_data['article_id'] = article.id
    article_data['user_id'] = article.owner.id
    article_data['title'] = article.title
    article_data['content'] = article.content
    article_data['category'] = article.category.title
    article_data['first_name'] = article.owner.first_name
    article_data['last_name'] = article.owner.first_name
    article_data['created_at'] = article.created_at
    article_data['updated_at'] = article.updated_at

    return render_template('single.html', post = article_data)

@app.route('/userarticles/<int:user_id>')
@login_required
def user_articles(user_id):
    articles = Article.query.filter_by(owner_id = user_id).all()

    output = []

    for article in articles:
        article_data = {}
        article_data['article_id'] = article.id
        article_data['user_id'] = article.owner.id
        article_data['title'] = article.title
        article_data['content'] = article.content
        article_data['category'] = article.category.title
        article_data['first_name'] = article.owner.first_name
        article_data['last_name'] = article.owner.first_name
        article_data['created_at'] = article.created_at
        article_data['updated_at'] = article.updated_at
        output.append(article_data)

    return render_template('userarticles.html', posts = output)

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():

    articles = Article.query.order_by(Article.updated_at.desc()).all()

    output = []

    for article in articles:
        article_data = {}
        article_data['article_id'] = article.id
        article_data['user_id'] = article.owner.id
        article_data['title'] = article.title
        article_data['content'] = article.content
        article_data['category'] = article.category.title
        article_data['first_name'] = article.owner.first_name
        article_data['last_name'] = article.owner.first_name
        article_data['created_at'] = article.created_at
        article_data['updated_at'] = article.updated_at
        output.append(article_data)

    return render_template('dashboard.html', posts = output)

@app.route('/logout')
@login_required
def logout():
    logout_user()

    session['active_user'] = ''

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
            new_article = Article(
                title = str(form.title.data), 
                content = str(form.content.data), 
                owner_id = current_user.id, 
                category_id = category_id,
                created_at = datetime.now(),
                updated_at = datetime.now()
            )
            db.session.add(new_article)
            db.session.commit()
            
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('create_article'))

    return render_template('createarticle.html', title = 'Create article', form = form)

@app.route('/deletearticle/<int:article_id>', methods=['POST'])
@login_required
def delete_article(article_id):
    article = Article.query.filter_by(id = article_id, owner_id = current_user.id).first()

    if article:
        db.session.delete(article)
        db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/article/update/<article_id>', methods=['GET', 'POST'])
@login_required
def update_article(article_id):
    article = Article.query.get_or_404(article_id)
    
    form = CreateArticleForm()
    form.categories.choices = [(c.id, c.title) for c in Category.query.order_by(Category.id.asc()).all()]

    if article and request.method == 'GET':
        form.title.data = article.title
        form.content.data = article.content

    if article and request.method == 'POST' and form.validate_on_submit():
        index = int( form.categories.data )
        category_id = form.categories.choices[index - 1][0]

        article.title = str(form.title.data)
        article.content = str(form.content.data)
        article.category_id = category_id
        article.updated_at = datetime.now()

        db.session.commit()

        return redirect(url_for('single_article', article_id = article_id))

    return render_template('updatearticle.html', id = { 'article': article_id }, form = form)

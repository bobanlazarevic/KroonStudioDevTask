from flask import Flask, render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_required

from blog.models import Article
from blog import app, db

dashboard_bp = Blueprint('dashboard_bp', __name__)

@dashboard_bp.route('/search', methods=['GET'])
@login_required
def search():
    keyword = request.args.get('query')
    results = Article.query.msearch(keyword, fields=['title', 'content'], limit=10)

    return render_template('dashboard.html', search_results = results)

@dashboard_bp.route('/single/<int:article_id>')
@login_required
def single_article(article_id):
    article = Article.query.get_or_404(article_id)

    return render_template('single.html', post = marshmallow_data(article))

@dashboard_bp.route('/userarticles/<int:user_id>')
@login_required
def user_articles(user_id):
    articles = Article.query.filter_by(owner_id = user_id).all()

    output = []
    for article in articles:
        output.append( marshmallow_data(article) )

    return render_template('userarticles.html', posts = output)

@dashboard_bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard():

    articles = Article.query.order_by(Article.updated_at.desc()).all()

    output = []
    for article in articles:
        output.append( marshmallow_data(article) )

    return render_template('dashboard.html', posts = output)

def marshmallow_data(article):
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

    return article_data
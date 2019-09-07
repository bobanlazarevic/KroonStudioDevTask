# from sqlalchemy import and_

from datetime import datetime
from flask import Flask, render_template, url_for, flash, redirect, request, Blueprint
from flask_login import current_user, login_required

from .forms import CreateArticleForm
from blog.models import Article, Category
from blog import db

articles_bp = Blueprint('articles_bp', __name__)

@articles_bp.route('/createarticle')
@login_required
def create_article():
    form = CreateArticleForm()
    form.categories.choices = [(c.id, c.title) for c in Category.query.order_by(Category.id.asc()).all()]

    return render_template('createarticle.html', form = form)

@articles_bp.route('/createarticle', methods=['POST'])
@login_required
def create_article_post():
    form = CreateArticleForm(request.form)
    form.categories.choices = [(c.id, c.title) for c in Category.query.order_by(Category.id.asc()).all()]

    #article = Article.query.filter(and_(Article.category_id == form.categories.data, Article.title == str(form.title.data))).first()

    if form.validate(): # and not article
        new_article = Article(
            title = str(form.title.data), 
            content = str(form.content.data), 
            owner_id = current_user.id, 
            category_id = form.categories.data,
            created_at = datetime.now(),
            updated_at = datetime.now()
        )
        db.session.add(new_article)
        db.session.commit()

        return redirect(url_for('dashboard_bp.dashboard'))

    flash('Article are not created, input was not valid!')
    return redirect(url_for('article_bp.create_article'))


@articles_bp.route('/deletearticle/<int:article_id>', methods=['POST'])
@login_required
def delete_article(article_id):
    article = Article.query.filter_by(id = article_id, owner_id = current_user.id).first()

    if article:
        db.session.delete(article)
        db.session.commit()

    return redirect(url_for('dashboard_bp.dashboard'))

@articles_bp.route('/article/update/<article_id>', methods=['GET', 'POST'])
@login_required
def update_article(article_id):
    article = Article.query.get_or_404(article_id)
    
    form = CreateArticleForm(request.form)
    form.categories.choices = [(c.id, c.title) for c in Category.query.order_by(Category.id.asc()).all()]

    if article:
        if request.method == 'GET':
            form.title.data = article.title
            form.content.data = article.content

        if request.method == 'POST' and form.validate():
            index = int( form.categories.data )
            category_id = form.categories.choices[index - 1][0]

            article.title = str(form.title.data)
            article.content = str(form.content.data)
            article.category_id = category_id
            article.updated_at = datetime.now()

            db.session.commit()
            
            return redirect(url_for('dashboard_bp.single_article', article_id = article_id))

    return render_template('updatearticle.html', form = form)
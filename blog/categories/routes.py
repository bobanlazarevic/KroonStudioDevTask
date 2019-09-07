from flask import Flask, render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_required

from .forms import CreateCategoryForm
from blog.models import Category
from blog import db

categories_bp = Blueprint('categories_bp', __name__)

@categories_bp.route('/category')
@login_required
def add_category():
    form = CreateCategoryForm()
    return render_template('createcategory.html', form = form)

@categories_bp.route('/category', methods=['POST'])
@login_required
def add_category_post():
    form = CreateCategoryForm(request.form)

    if form.validate():
        new_category = Category(title = request.form.get('title').lower())
        db.session.add(new_category)
        db.session.commit()
            
        return redirect(url_for('dashboard_bp.dashboard'))

    for error in form.errors.items():
        flash(error[0].capitalize() + ': '+ str(error[1][0]))

    return redirect(url_for('categories_bp.add_category'))
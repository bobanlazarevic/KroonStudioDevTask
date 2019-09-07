from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

from flask_msearch import Search

app = Flask(__name__, template_folder='../templates', static_folder='../static')

app.config['SECRET_KEY'] = 'ovojetajnasifra'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

db = SQLAlchemy(app)

search = Search(db = db)
search.init_app(app)

login = LoginManager(app)
login.login_view = 'users_bp.login'

from .models import User

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

from blog.users.routes import users_bp
from blog.articles.routes import articles_bp
from blog.dashboard.routes import dashboard_bp
from blog.categories.routes import categories_bp

app.register_blueprint(users_bp)
app.register_blueprint(articles_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(categories_bp)

@app.errorhandler(404)
def error_404(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(405)
def error_405(error):
    return render_template('errors/405.html'), 405

@app.errorhandler(500)
def error_500(error):
    return render_template('errors/500.html'), 500

from blog import models

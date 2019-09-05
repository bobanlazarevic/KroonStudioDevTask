from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

from flask_msearch import Search

app = Flask(__name__, template_folder='../templates', static_folder='../static')

app.config['SECRET_KEY'] = 'SamoZaTvojeOci'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

db = SQLAlchemy(app)

search = Search(db = db)
search.init_app(app)

login = LoginManager(app)
login.login_view = 'login'

from .models import User

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

from blog import routes, models

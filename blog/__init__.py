from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SamoZaTvojeOci'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

db = SQLAlchemy(app)

login = LoginManager(app)
login.login_view = 'dummy'

from .models import User

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

from blog import routes, models

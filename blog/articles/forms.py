from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length
from blog.models import *

class CreateArticleForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators= [DataRequired(), Length(min=2, max=2000)])
    categories = SelectField('Categories', coerce=int, validators=[DataRequired()])
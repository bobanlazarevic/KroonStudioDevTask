from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, Length, ValidationError
from blog.models import *

class CreateCategoryForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(min=2, max=40)])

    def validate_title(self, title):
        category = Category.query.filter_by(title = title.data.lower()).first()
        if category:
            raise ValidationError('Category with that name already exists!')
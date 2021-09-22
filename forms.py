# from flask_wtf import FlaskForm
# from wtforms import StringField, SubmitField, PasswordField, SelectField, IntegerField, TextAreaField
# from wtforms.validators import DataRequired, URL, Email, EqualTo
# from wtforms.ext.sqlalchemy.fields import QuerySelectField
# from flask_ckeditor import CKEditorField
# from tables import db, Category
#
#
# # # WTForm
#
# class CreatePostForm(FlaskForm):
#     title = StringField("Blog Post Title", validators=[DataRequired()])
#     subtitle = StringField("Subtitle", validators=[DataRequired()])
#     img_url = StringField("Blog Image URL", validators=[DataRequired(), URL(require_tld=True)])
#     body = CKEditorField("Blog Content", validators=[DataRequired()])
#     all_categories = db.session.query(Category).order_by(Category.name).all()
#     all_categories_name = [category.name for category in all_categories]
#     category = SelectField(u"Choose the category that best suits your Blog", validators=[DataRequired()],
#                            choices=all_categories_name)
#     submit = SubmitField("Submit Post")
#
#
# class RegisterForm(FlaskForm):
#     username = StringField(label="Username", validators=[DataRequired()])
#     email = StringField(label="Email", validators=[DataRequired(), Email(granular_message=True, check_deliverability=True)])
#     password = PasswordField(label="Password", validators=[DataRequired(), EqualTo(fieldname='password_check', message="Passwords must match")])
#     password_check = PasswordField(label="Confirm Password", validators=[DataRequired()])
#     submit = SubmitField(label="Sign Me Up!")
#
#
# class LoginForm(FlaskForm):
#     email = StringField(label="Email", validators=[DataRequired()])
#     password = PasswordField(label="Password", validators=[DataRequired()])
#     submit = SubmitField(label="Log Me In!")
#
#
# class CommentForm(FlaskForm):
#     comment = CKEditorField(label="Comment", validators=[DataRequired()])
#     submit = SubmitField(label="Post Comment")
#
#
# class SearchForm(FlaskForm):
#     keyword = StringField(label="Search for blogs or users", validators=[DataRequired()])
#     selections = SelectField(label="Choose your Scope", choices=["Users", "Blog Posts"])
#     submit = SubmitField(label="Search")
#
#
# class GetInTouchForm(FlaskForm):
#     name = StringField(label="Name", validators=[DataRequired()])
#     phone = IntegerField(label="Phone", validators=[DataRequired()])
#     email = StringField(label="Email", validators=[DataRequired(), Email(granular_message=True, check_deliverability=True)])
#     message = TextAreaField(label="Message", validators=[DataRequired()])
#
#
# # class ResetForm(FlaskForm):
# #     password = StringField()
# #     confirm_pass = StringField()

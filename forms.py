# from flask_wtf import FlaskForm
# from wtforms import StringField, SubmitField, PasswordField, SelectField
# from wtforms.validators import DataRequired, URL, Email, EqualTo
# from wtforms.ext.sqlalchemy.fields import QuerySelectField
# from flask_ckeditor import CKEditorField
# from main import all_categories_name


# # # WTForm
# class CreatePostForm(FlaskForm):
#     title = StringField("Blog Post Title", validators=[DataRequired()])
#     subtitle = StringField("Subtitle", validators=[DataRequired()])
#     img_url = StringField("Blog Image URL", validators=[DataRequired(), URL(require_tld=True)])
#     body = CKEditorField("Blog Content", validators=[DataRequired()])
#     category = SelectField(u"Choose the category that best suits your Blog", validators=[DataRequired()],
#                            choices=["Architecture & Design", "Technology"])
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
# # class ResetForm(FlaskForm):
# #     password = StringField()
# #     confirm_pass = StringField()

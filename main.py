from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, SelectField, IntegerField, TextAreaField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_uploads import UploadSet, IMAGES
from werkzeug.utils import secure_filename
from wtforms.validators import DataRequired, URL, Email, EqualTo
from wtforms.ext.sqlalchemy.fields import QuerySelectField
from flask_ckeditor import CKEditorField
from functools import wraps, update_wrapper
import smtplib
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# # CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:86IamAnkush@localhost:5432/blogs'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 5 * 1000 * 1000
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# # CONFIGURE TABLES

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    short_desc = db.Column(db.Text)
    long_desc = db.Column(db.Text)
    pfp_name = db.Column(db.String(300))
    pfp_data = db.Column(db.LargeBinary)
    # Adding a 1:N relationship between User and BlogPost
    posts = relationship("BlogPost", back_populates="author")   # Step 1, also step 3 (back_populates)
    # Adding a 1:N relationship between User and Comment
    comments = relationship("Comment", back_populates="commenter")
    # Adding a N:N relationship between User and Category (Interests) remains


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    datetime = db.Column(db.DateTime, nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Adding a author_id Foreign Key with bidirectional 1:N relationship between User and BlogPost
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)  # Step 2
    author = relationship("User", back_populates="posts")  # Step 3
    # Adding a category_id Foreign Key with bidirectional 1:N relationship between Category and BlogPost
    category_id = db.Column(db.Integer, db.ForeignKey("categories.id"), nullable=False)
    category = relationship("Category", back_populates="posts")
    # 1:N relationship between BlogPost and Comment
    comments = relationship("Comment", back_populates="parent_post")


class Category(db.Model):
    __tablename__ = "categories"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    # Adding a 1:N relationship between Category and BlogPost
    posts = relationship("BlogPost", back_populates="category")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # Adding a commenter_id Foreign Key with bidirectional 1:N relationship between User and Comment
    commenter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    commenter = relationship("User", back_populates="comments")
    # Adding a post_id Foreign Key with bidirectional 1:N relationship between BlogPost and Comment
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)   # Content of the comment
    datetime = db.Column(db.DateTime, nullable=False)


db.create_all()
# all_categories = db.session.query(Category).order_by(Category.name).all()
# print(all_categories)
# all_categories_name = [category.name for category in all_categories]
# print(all_categories_name)


# # WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL(require_tld=True)])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    all_categories = db.session.query(Category).order_by(Category.name).all()
    all_categories_name = [category.name for category in all_categories]
    category = SelectField(u"Choose the category that best suits your Blog", validators=[DataRequired()],
                           choices=all_categories_name)
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    username = StringField(label="Username", validators=[DataRequired()])
    email = StringField(label="Email", validators=[DataRequired(), Email(granular_message=True, check_deliverability=True)])
    password = PasswordField(label="Password",
                             validators=[DataRequired(), EqualTo(fieldname='password_check', message="Passwords must match")])
    password_check = PasswordField(label="Confirm Password", validators=[DataRequired()])
    submit = SubmitField(label="Sign Me Up!")


class LoginForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="Log Me In!")


class CommentForm(FlaskForm):
    comment = CKEditorField(label="Comment", validators=[DataRequired()])
    submit = SubmitField(label="Post Comment")


class SearchForm(FlaskForm):
    keyword = StringField(label="Search for blogs or users", validators=[DataRequired()])
    selections = SelectField(label="Choose your Scope", choices=["Users", "Blog Posts"])
    submit = SubmitField(label="Search")


class GetInTouchForm(FlaskForm):
    name = StringField(label="Name", validators=[DataRequired()])
    phone = IntegerField(label="Phone", validators=[DataRequired()])
    email = StringField(label="Email",
                        validators=[DataRequired(), Email(granular_message=True, check_deliverability=True)])
    message = TextAreaField(label="Message", validators=[DataRequired()])
    submit = SubmitField(label="Send Message")


class EditProfileForm(FlaskForm):
    username = StringField(label="Username", validators=[DataRequired()])
    email = StringField(label="Email",
                        validators=[DataRequired(), Email(granular_message=True, check_deliverability=True)])
    short_desc = CKEditorField(label="A short introduction of yours", validators=[DataRequired()])
    long_desc = CKEditorField(label="Describe yourself to your readers", validators=[DataRequired()])
    pfp = FileField(label="Upload a Profile Picture with max-size 5 MB (only .jpeg, .png and .gif accepted)",
                    validators=[FileAllowed(upload_set=UploadSet('images', IMAGES), message="Images only!")])
    submit = SubmitField("Confirm Changes")

# class ResetForm(FlaskForm):
#     password = StringField()
#     confirm_pass = StringField()


login_manager = LoginManager(app=app)


def admin_only(func):
    @wraps(func)                      # Or use update_wrapper function once the wrapper/decorated function is defined
    def decorated_function(*args, **kwargs):
        if current_user.id == 1 and current_user.is_authenticated:
            return func(*args, **kwargs)
        else:
            return abort(403)
        
    # update_wrapper(decorated_function, func)    # Can be used instead of @wraps(func) above decorated function def
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    print(f"The user logged in currently under login_manager.user_loader is {user_id}")
    return User.query.get(int(user_id))


@app.route('/')
def home():
    posts = db.session.query(BlogPost).all()
    all_categories = Category.query.order_by(Category.name).all()
    print(all_categories)
    # posts_per_category = {category.id: len(category.posts) for category in all_categories}
    # print(posts_per_category)       # Gives (category id, number of posts) key-value pair
    # sorted_number_of_posts = sorted(posts_per_category.values(), reverse=True)
    # print(sorted_number_of_posts)   # Gives highest to lowest post-count
    # popular_categories = {posts_per_category.get(number): number for number in sorted_number_of_posts}
    # print(popular_categories)       #
    # Second try : Just getting the travel, art and photography categories (Both ways work:)
    # all_travel_posts = db.session.query(BlogPost).filter_by(category_id=17).all()
    # all_art_posts = db.session.query(BlogPost).filter_by(category_id=<find_id_in_db>).all()
    # all_photography_posts = db.session.query(BlogPost).filter_by(category_id=<find_id_in_db>).all()

    # all_travel_posts = db.session.query(Category).filter_by(name="Travel").first().posts
    # all_art_posts = db.session.query(Category).filter_by(name="Art").first().posts
    # all_photography_posts = db.session.query(Category).filter_by(name="Photography").first().posts
    return render_template("index.html", all_posts=posts, all_categories=all_categories)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        print("POST request for register form successful")
        if db.session.query(User).filter_by(email=register_form.email.data).first():
            flash("Your email is already registered. Log in instead!")
            return redirect(url_for("login"))

        elif db.session.query(User).filter_by(username=register_form.username.data).first():
            flash("Username is already taken. Please choose something else!")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password=register_form.password.data, method="pbkdf2:sha256", salt_length=8)
        new_user = User(username=register_form.username.data, email=register_form.email.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home"))

    return render_template("register.html", form=register_form, all_categories=Category.query.order_by(Category.name).all())


@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    login_form = LoginForm()
    if login_form.validate_on_submit():
        print("POST request for login form successful")
        user_to_check = db.session.query(User).filter_by(email=login_form.email.data).first()
        if user_to_check:
            if check_password_hash(pwhash=user_to_check.password, password=login_form.password.data):
                login_user(user_to_check)

                return redirect(url_for("home"))
            else:
                flash("Incorrect password entered! Please try again.")
                return redirect(url_for("login"))
        else:
            flash("The email you entered does not exist. Please try again.")
            return redirect(url_for("login"))

    return render_template("login.html", form=login_form, all_categories=Category.query.order_by(Category.name).all())


@app.route('/logout')
@login_required
def logout():
    logout_user()
    print(f"User ID: {current_user} logged out")
    return redirect(url_for('home'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    post_author_id = requested_post.author_id
    other_posts_by_same_author = BlogPost.query.filter_by(author_id=post_author_id).all()
    other_posts_by_same_author.remove(requested_post)   # Removing the current post
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(text=comment_form.comment.data, commenter=current_user,
                                  parent_post=requested_post, datetime=datetime.utcnow())
            db.session.add(new_comment)
            db.session.commit()     # Following line is optional, as it would lead to the final return render_template
            # return redirect(url_for("show_post", post_id=post_id))    # statement, to render the same page.
        else:
            flash("You need to login or register to comment")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=comment_form, comments=requested_post.comments,
                           related_posts=other_posts_by_same_author[:3:],
                           all_categories=Category.query.order_by(Category.name).all())


@app.route("/about-us", methods=["GET", "POST"])
def about_us():
    form = GetInTouchForm()
    confirmation_msg = None
    # print(confirmation_msg)
    if form.validate_on_submit():
        mail_contents = f"Name: {form.name.data}\nPhone: {form.phone.data}\nEmail: {form.email.data}\n" \
                        f"Message:\n{form.message.data}"
        # print(mail_contents)
        with smtplib.SMTP(host="smtp.gmail.com", port=587) as connection:
            connection.starttls()
            connection.login(user="ankushbhowmiktesting@gmail.com", password="Ankush123*()")
            connection.sendmail(from_addr="ankushbhowmiktesting@gmail.com", to_addrs="ankushbhowmiktesting@gmail.com",
                                msg=f"Subject:Marcian Blogs - Get In Touch\n\n{mail_contents}")
        confirmation_msg = "Message Sent Successfully"
    else:
        print("Form not validated")
    return render_template("about-us.html", form=form, confirmation_msg=confirmation_msg,
                           all_categories=Category.query.order_by(Category.name).all())


# @app.route("/contact")    # Not required, as /about-us has pretty much the same content, including the contact form
# def contact():
#     return render_template("contact-us.html")


@app.route("/new-post", methods=["GET", "POST"])
# @admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        print(form.category.data, type(form.category.data))
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            datetime=datetime.utcnow(),
            category=db.session.query(Category).filter_by(name=form.category.data).first()
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("make-post.html", form=form, all_categories=Category.query.order_by(Category.name).all())


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
# @admin_only
def edit_post(post_id):
    post = db.session.query(BlogPost).get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body,
        category=post.category.name
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        post.category = db.session.query(Category).filter_by(name=edit_form.category.data).first()
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", post=post, form=edit_form, is_edit=True,
                           all_categories=Category.query.order_by(Category.name).all())


@app.route("/delete-post/<int:post_id>")
# @admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/delete-comment/<int:comment_id>")
def delete_comment(comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for("show_post", post_id=comment_to_delete.post_id ))


@app.errorhandler(403)
def access_denied(error):       # This arg is required, probably some other function passes something, as error shows
    return render_template("error403.html"), 403    # access_denied takes 0 positional arg, but 1 one was given


@app.errorhandler(404)
def access_denied(error):
    return render_template("page-404.html", all_categories=Category.query.order_by(Category.name).all())


# For development purpose only
# @app.route("/posts")      # /post/<int:post_id> route is working so commented
# def show_posts():
#     comment_form = CommentForm()
#     return render_template("post.html", form=comment_form)


@app.route("/user/<int:user_id>")
def posts_by_user(user_id):
    user = db.session.query(User).get(user_id)
    blogs_from_this_user = user.posts
    return render_template("user_page.html", user=user, user_posts=blogs_from_this_user,
                           all_categories=Category.query.order_by(Category.name).all())


@app.route("/user/<int:user_id>/profile", methods=["GET", "POST"])
def show_user_profile(user_id):
    user = db.session.query(User).get(user_id)
    form = GetInTouchForm()
    confirmation_msg = None
    if form.validate_on_submit():
        mail_contents = f"Name: {form.name.data}\nPhone: {form.phone.data}\nEmail: {form.email.data}\n" \
                        f"Message:\n{form.message.data}"
        with smtplib.SMTP(host="smtp.gmail.com", port=587) as connection:
            connection.starttls()
            connection.login(user="ankushbhowmiktesting@gmail.com", password="Ankush123*()")
            connection.sendmail(from_addr="ankushbhowmiktesting@gmail.com", to_addrs=user.email,
                                msg=f"Subject:Marcian Blogs - User Wants to contact you\n\n {mail_contents}")

            confirmation_msg = "Mail sent successfully"
    else:
        print("Form not validated")

    return render_template("user-profile-contact.html", user=user, form=form, confirmation_msg=confirmation_msg,
                           all_categories=Category.query.order_by(Category.name).all())


@app.route("/user/<int:user_id>/profile/edit", methods=["GET", "POST"])
def edit_user_profile(user_id):
    user = db.session.query(User).get(user_id)
    edit_profile_form = EditProfileForm(username=user.username, email=user.email,
                                        short_desc=user.short_desc, long_desc=user.long_desc)
    if edit_profile_form.validate_on_submit():
        user.username = edit_profile_form.username.data
        user.email = edit_profile_form.email.data
        user.short_desc = edit_profile_form.short_desc.data
        user.long_desc = edit_profile_form.long_desc.data
        db.session.commit()
        return redirect(url_for("show_user_profile", user_id=user.id))      # Or user_id=user_id

    return render_template("edit-user-profile.html", user=user, form=edit_profile_form,
                           all_categories=Category.query.order_by(Category.name).all())


@app.route("/category/<int:cat_id>")
def posts_by_category(cat_id):
    category = db.session.query(Category).get(cat_id)
    return render_template("posts-by-category.html", category=category,
                           all_categories=Category.query.order_by(Category.name).all())


# @app.route("/make-a-new-post/")   # /new-post route is working so commented
# def make_a_new_post():
#     create_post_form = CreatePostForm()
#     return render_template("make-post.html", form=create_post_form)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

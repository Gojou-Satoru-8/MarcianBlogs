from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from functools import wraps, update_wrapper

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
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
    date = db.Column(db.String(250), nullable=False)
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
    name = db.Column(db.String, unique=True, nullable=False)
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

# db.create_all()


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


@app.errorhandler(403)
def access_denied(error):       # This arg is required, probably some other function passes something, as error shows
    return render_template("error403.html"), 403    # access_denied takes 0 positional arg, but 1 one was given


@app.errorhandler(404)
def access_denied(error):
    return render_template("page-404.html")


@login_manager.user_loader
def load_user(user_id):
    print(f"The user logged in currently under login_manager.user_loader is {user_id}")
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if db.session.query(User).filter_by(email=register_form.email.data).first():
            flash("Your email is already registered. Log in instead!")
            return redirect(url_for("login"))

        hashed_pw = generate_password_hash(password=register_form.password.data, method="pbkdf2:sha256", salt_length=8)
        new_user = User(name=register_form.name.data, email=register_form.email.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))

    return render_template("page-register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("get_all_posts"))
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user_to_check = db.session.query(User).filter_by(email=login_form.email.data).first()
        if user_to_check:
            if check_password_hash(pwhash=user_to_check.password, password=login_form.password.data):
                login_user(user_to_check)

                return redirect(url_for("get_all_posts"))
            else:
                flash("Incorrect password entered! Please try again.")
                return redirect(url_for("login"))
        else:
            flash("The email you entered does not exist. Please try again.")
            return redirect(url_for("login"))

    return render_template("page-login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(text=comment_form.comment.data, commenter_id=current_user.id, post_id=post_id)
            db.session.add(new_comment)
            db.session.commit()     # Following line is optional, as it would lead to the final return render_template
            # return redirect(url_for("show_post", post_id=post_id))    # statement, to render the same page.
        else:
            flash("You need to login or register to comment")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=comment_form, comments=requested_post.comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)

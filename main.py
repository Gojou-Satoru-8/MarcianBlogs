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

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Linking the two two tables via 1:N relationshp between User to BlogPost:
    # 1st step is specifying relationship (posts = relationship("BlogPost") line) in the parent table. posts will be a
    # field that doesn't appear on the table. Rather, relationship() field/variable is only for specifying relationships

    # 2nd step is creating a new column for the Foreign Key in the child table, here it's author_id which takes in
    # users.id primary key value from User class ie. users table (the parent table here)
    # Remember: inside db.ForeignKey(), the parameter is "__tablename__.<primary_key of parent table>"
    # Thus, for the User class table with __tablename__ = "users", it is users.id not User.id

    # 3rd step (bidirectional relationship) : use back_populates="relationship field name" inside relationship() field
    # or variable inside both the parent and child class. As BlogPost class (child table) does not normally require a
    # relationship() field (relationships are only specified on the parent), for this case, create a relationship()
    # field inside the BlogPost, which back_populates to the relationship() field int User class, ie users table.
    # Remember: inside relationship(), the parameters are : (1)Table Class Name, here, the value of __tablename__
    # and (2) back-populates =<The relationship field name in the other table>

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)    # Step 2

    # Following Columns were there from before
    author = relationship("User", back_populates="posts")   # Step 3
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # 1:N relationship between BlogPost and Comment
    comments = relationship("Comment", back_populates="parent_post")
    
# db.create_all()


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    posts = relationship("BlogPost", back_populates="author")   # Step 1, also step 3 (back_populates)
    comments = relationship("Comment", back_populates="commenter")
# Note that whenever you access relationship() fields, say you query a BlogPost object, and tap into the author
# property, like post1 = db.session.query(BlogPost).get(1), then author1 = post1.author, it will return the entire User
# object. From there, you can access all properties of the User object, ie. author1.name (or id, password) et...


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # 1:N relationship between User to Comment
    commenter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    commenter = relationship("User", back_populates="comments")
    # 1:N relationship between BlogPost to Comment
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)   # Content of the comment


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

    return render_template("register.html", form=register_form)


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
                # flash("Logged in successfully!")  # If flash messages aren't printed with Jinja in the right html
                # file, they are stored in buffer, until user loads up a page where the flashed messages are
                # caught with get_flashed_messages() function followed by: {{ message }}, which means that even if the
                # page was supposed to deliver some other message/ no message (depending on return statements under that
                # route, the original message will be delivered. Hence, please make sure of the order.
                return redirect(url_for("get_all_posts"))
            else:
                flash("Incorrect password entered! Please try again.")
                return redirect(url_for("login"))
        else:
            flash("The email you entered does not exist. Please try again.")
            return redirect(url_for("login"))

    return render_template("login.html", form=login_form)


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

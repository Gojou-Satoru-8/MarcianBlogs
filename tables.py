# from main import app
# from flask_sqlalchemy import SQLAlchemy
# from sqlalchemy.orm import relationship
# from flask_login import UserMixin
#
#
# db = SQLAlchemy(app)
#
#
# # # CONFIGURE TABLES
#
# class User(db.Model, UserMixin):
#     __tablename__ = "users"
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(250), nullable=False)
#     email = db.Column(db.String(100), unique=True, nullable=False)
#     password = db.Column(db.String(100), nullable=False)
#     # Adding a 1:N relationship between User and BlogPost
#     posts = relationship("BlogPost", back_populates="author")   # Step 1, also step 3 (back_populates)
#     # Adding a 1:N relationship between User and Comment
#     comments = relationship("Comment", back_populates="commenter")
#     # Adding a N:N relationship between User and Category (Interests) remains
#
#
# class BlogPost(db.Model):
#     __tablename__ = "blog_posts"
#     id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String(250), unique=True, nullable=False)
#     subtitle = db.Column(db.String(250), nullable=False)
#     date = db.Column(db.String(250), nullable=False)
#     body = db.Column(db.Text, nullable=False)
#     img_url = db.Column(db.String(250), nullable=False)
#     # Adding a author_id Foreign Key with bidirectional 1:N relationship between User and BlogPost
#     author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)  # Step 2
#     author = relationship("User", back_populates="posts")  # Step 3
#     # Adding a category_id Foreign Key with bidirectional 1:N relationship between Category and BlogPost
#     category_id = db.Column(db.Integer, db.ForeignKey("categories.id"), nullable=False)
#     category = relationship("Category", back_populates="posts")
#     # 1:N relationship between BlogPost and Comment
#     comments = relationship("Comment", back_populates="parent_post")
#
#
# class Category(db.Model):
#     __tablename__ = "categories"
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(80), unique=True, nullable=False)
#     # Adding a 1:N relationship between Category and BlogPost
#     posts = relationship("BlogPost", back_populates="category")
#
#
# class Comment(db.Model):
#     __tablename__ = "comments"
#     id = db.Column(db.Integer, primary_key=True)
#     # Adding a commenter_id Foreign Key with bidirectional 1:N relationship between User and Comment
#     commenter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
#     commenter = relationship("User", back_populates="comments")
#     # Adding a post_id Foreign Key with bidirectional 1:N relationship between BlogPost and Comment
#     post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
#     parent_post = relationship("BlogPost", back_populates="comments")
#     text = db.Column(db.Text, nullable=False)   # Content of the comment
#     date = db.Column(db.String(50), nullable=False)
#
#
# db.create_all()
# all_categories = db.session.query(Category).order_by(Category.name).all()
# print(all_categories)
# all_categories_name = [category.name for category in all_categories]
# print(all_categories_name)

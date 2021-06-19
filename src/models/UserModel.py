from . import db

class User(db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String, unique=True)
    first_name = db.Column(db.String(32))
    last_name = db.Column(db.String(32))
    username = db.Column(db.String(128), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    is_staff = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime)
    modified_at = db.Column(db.DateTime)
    blogposts = db.relationship('BlogpostModel', backref='users', lazy=True)
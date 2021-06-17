from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os
import re

app = Flask(__name__)

uri = os.environ['DATABASE_URL']
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)

app.config['SECRET_KEY'] = os.environ['SECRET_KEY'] #"thisisasecretkey" 
app.config['SQLALCHEMY_DATABASE_URI'] = uri #os.environ['DATABASE_URL'] #'postgresql://postgres:1212@localhost/testdbapi' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer, unique=True)
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

class BlogpostModel(db.Model):

    __tablename__ = 'blogposts'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    contents = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime)
    modified_at = db.Column(db.DateTime)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/')
def index():
    return jsonify({'message': 'lol xd'})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id = str(uuid.uuid4()), first_name = data['first_name'], last_name = data['last_name'], username = data['username'], password = hashed_password, email = data['email'], email_verified = True, is_staff = True, is_admin = True, created_at = datetime.datetime.utcnow(), modified_at=datetime.datetime.utcnow())
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' :'New user created!', 'success' : 'True'})


if __name__ == '__main__':
    app.debug = True
    app.run()
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

FLASK_ENV = os.environ['FLASK_ENV']

if FLASK_ENV == 'production':
    print("PRODUCTION ENVIROMENT")
    uri = os.environ['DATABASE_URL']
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)

    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
    app.config['SQLALCHEMY_DATABASE_URI'] = uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

else:
    print("DEVELOPMENT ENVIROMENT")
    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

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

class BlogpostModel(db.Model):

    __tablename__ = 'blogposts'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    contents = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime)
    modified_at = db.Column(db.DateTime)

def create_tokens(username_input):

    user = User.query.filter_by(username=username_input).first()

    matchid = str(uuid.uuid4())

    token_content = {
        'public_id' : user.public_id,
        'first_name' : user.first_name,
        'last_name' : user.last_name,
        'username' : user.username,
        'email' : user.email,
        'email_verified' : user.email_verified,
        'is_staff' : user.is_staff,
        'is_admin' : user.is_admin,
        'created_at' : str(user.created_at),
        'modified_at' : str(user.modified_at),
        'tokenmatchid' : matchid,
        'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }

    refresh_token_content = {
        'public_id' : user.public_id,
        'username' : user.username,
        'email' : user.email,
        'refreshtokenmatchid' : matchid,
        'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }

    token = jwt.encode(token_content, app.config['SECRET_KEY'])
    refresh_token = jwt.encode(refresh_token_content, app.config['SECRET_KEY'])

    list_of_tokens = [token, refresh_token]

    return list_of_tokens

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

        except jwt.ExpiredSignatureError:
            return jsonify({'message' : 'Token is expired!', 'expired' : True}), 403

        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/')
def index():
    return jsonify({'message': 'lol xd'})

@app.route('/login',  methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):

        list_of_tokens = create_tokens(auth.username)

        token = list_of_tokens[0]
        refresh_token = list_of_tokens[1]

        return jsonify({'token' : token.decode('UTF-8'), 'refresh_token' : refresh_token.decode('UTF-8'), 'success': True})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/refresh', methods=['POST'])
def refresh_token():
    if 'x-access-token' in request.headers:
        access_token = request.headers['x-access_token']
        if not access_token:
            return jsonify({'message' : 'Token is missing!', 'success': False}), 401

    if 'x-refresh-token' in request.headers:
        refresh_token = request.headers['x-refresh-token']
        if not refresh_token:
            return jsonify({'message' : 'Token is missing!', 'success': False}), 401

    try: 
        data = jwt.decode(access_token, app.config['SECRET_KEY'])
        return jsonify({'message' : 'Access Token is still valid', 'success': False})

    except jwt.ExpiredSignatureError:
        try:
            refresh_token_data = jwt.decode(refresh_token, app.config['SECRET_KEY'])

        except jwt.ExpiredSignatureError:
            return jsonify({'message' : 'Refresh Token is expired. login again', 'success': False}), 406

        except:
            return jsonify({'message' : 'Refresh Token is invalid', 'success': False})
        access_token_data = jwt.decode(access_token, app.config['SECRET_KEY'], options={"verify_exp" : False})

        if refresh_token_data['refreshtokenmatchid'] == access_token_data['tokenmatchid']:
            list_of_tokens = create_tokens(refresh_token_data['username'])

            token = list_of_tokens[0]
            refresh_token = list_of_tokens[1]

            return jsonify({'token' : token.decode('UTF-8'), 'refresh_token' : refresh_token.decode('UTF-8'), 'success': True})
        
        return jsonify({'message' : 'Tokens does not match', 'success': False})
    
    except:
        return jsonify({'message' : 'Invalid tokens', 'success': False})

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.is_admin:
        return jsonify({'message' : 'Cannot perform that function!', 'success' : False})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['first_name'] = user.first_name
        user_data['last_name']=user.last_name
        user_data['username'] = user_data.username
        user_data['email'] = user.email
        user_data['email_verified'] = user.email_verified
        user_data['is_staff'] = user.is_staff
        user_data['is_admin'] = user.is_admin
        user_data['created_at'] = user.created_at
        user_data['modified_at'] = user.modified_at
        output.append(user_data)

    return jsonify({'users' : output, 'success' : True})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.is_admin:
        return jsonify({'message' : 'Cannot perform that function!', 'success' : False})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!', 'success' : False})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['first_name'] = user.first_name
    user_data['last_name']=user.last_name
    user_data['username'] = user_data.username
    user_data['email'] = user.email
    user_data['email_verified'] = user.email_verified
    user_data['is_staff'] = user.is_staff
    user_data['is_admin'] = user.is_admin
    user_data['created_at'] = user.created_at
    user_data['modified_at'] = user.modified_at

    return jsonify({'user' : user_data, 'success' : True})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(
        public_id = str(uuid.uuid4()), 
        first_name = data['first_name'], 
        last_name = data['last_name'], 
        username = data['username'], 
        password = hashed_password, 
        email = data['email'], 
        email_verified = False, 
        is_staff = False, 
        is_admin = False, 
        created_at = datetime.datetime.utcnow(), 
        modified_at=datetime.datetime.utcnow()
        )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' :'New user created!', 'success' : True})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user_to_staff(current_user, public_id):
    if not current_user.is_admin:
        return jsonify({'message' : 'Cannot perform that function', 'success' : False})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found', 'success' : False})

    user.is_staff = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted to staff', 'success' : True})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user_to_admin(current_user, public_id):
    if not current_user.is_admin:
        return jsonify({'message' : 'Cannot perform that function', 'success' : False})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found', 'success' : False})

    user.is_admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted to admin', 'success' : True})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.is_admin:
        return jsonify({'message' : 'Cannot perform that function', 'success' : False})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!', 'success' : False})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!', 'success' : True})    


if __name__ == '__main__':
    app.debug = True
    app.run()
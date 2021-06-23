from flask import jsonify, request, make_response, Blueprint, g, redirect
from ..models.UserModel import User
from ..models import db
from werkzeug.security import generate_password_hash, check_password_hash
from ..shared.authentication import create_tokens, token_required, send_conf_email
import jwt
import os
import uuid
import datetime
from urllib.parse import urlencode

user_api = Blueprint('user_api', __name__)

@user_api.route('/', methods=['POST'])
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

@user_api.route('/me', methods=['GET'])
@token_required
def view_self_info(current_user):

    user_data = {}
    user_data['public_id'] = current_user.public_id
    user_data['first_name'] = current_user.first_name
    user_data['last_name'] = current_user.last_name
    user_data['username'] = current_user.username
    user_data['email'] = current_user.email
    user_data['email_verified'] = current_user.email_verified
    user_data['is_staff'] = current_user.is_staff
    user_data['is_admin'] = current_user.is_admin
    user_data['created_at'] = current_user.created_at
    user_data['modified_at'] = current_user.modified_at

    return jsonify({'user' : user_data, 'success' : True})

@user_api.route('/me', methods=['PUT'])
@token_required
def update_self_info(current_user):
    data = request.get_json()

    success = {}

    if data['first_name']:
        if current_user.first_name != data['first_name']:
            current_user.first_name = data['first_name']
            success['first_name_success'] = True

    if data['last_name']:
        if current_user.last_name != data['last_name']:
            current_user.last_name = data['last_name']
            success['last_name_success'] = True

    if data['username']:
        if current_user.username != data['username']:
            user = User.query.filter_by(username=data['username']).first()
            if not user:
                success['username_success'] = True
                current_user.username = data['username']
            success['username_success'] = False

    if data['email']:
        if current_user.email != data['email']:
            user = User.query.filter_by(email=data['email']).first()
            if not user:
                success['email_success'] = True
                current_user.email = data['email']
                current_user.email_verified = False
            success['email_success'] = False
    if success:        
        current_user.modified = datetime.datetime.utcnow()
        db.session.commit()
        return jsonify(success)
    return jsonify({'success' : False})

@user_api.route('/me/change_password', methods=['PUT'])
@token_required
def change_password(current_user):
    data = request.get_json()

    if check_password_hash(current_user.password, data['old_password']):
        new_hashed_password = generate_password_hash(data['new_password'], method='sha256')
        current_user.password = new_hashed_password
        current_user.modified = datetime.datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success' : False}), 401

@user_api.route('/me/verify_email', methods=['POST'])
@token_required
def send_verification_email(current_user):

    token = request.headers['x-access-token']
    data = jwt.decode(token, os.environ['SECRET_KEY'])
    
    if not data['email_verified']:

        email_verification_token_content = {
            'public_id' : current_user.public_id,
            'username' : current_user.username,
            'email' : current_user.email,
            'email_verified' : current_user.email_verified,
            'exp' : datetime.datetime.utcnow() + datetime.timedelta(hours=3)
        }

        email_confirm_token = jwt.encode(email_verification_token_content, os.environ['SECRET_KEY'])
        qs = urlencode({"token": email_confirm_token})
        url = f"https://basic-login-jwt-flask-api.herokuapp.com/api/v1/confirm?{qs}"

        send_conf_email(current_user.email, url)
        return jsonify({'success': True})

    return jsonify({'success' :False, 'message': 'Your email is already verified'})

@user_api.route('/', methods=['GET'])
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
        user_data['last_name'] = user.last_name
        user_data['username'] = user.username
        user_data['email'] = user.email
        user_data['email_verified'] = user.email_verified
        user_data['is_staff'] = user.is_staff
        user_data['is_admin'] = user.is_admin
        user_data['created_at'] = user.created_at
        user_data['modified_at'] = user.modified_at
        output.append(user_data)

    return jsonify({'users' : output, 'success' : True})


@user_api.route('/<public_id>', methods=['GET'])
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
    user_data['last_name'] = user.last_name
    user_data['username'] = user.username
    user_data['email'] = user.email
    user_data['email_verified'] = user.email_verified
    user_data['is_staff'] = user.is_staff
    user_data['is_admin'] = user.is_admin
    user_data['created_at'] = user.created_at
    user_data['modified_at'] = user.modified_at

    return jsonify({'user' : user_data, 'success' : True})

@user_api.route('/<public_id>', methods=['PUT'])
@token_required
def promote_user_to_admin(current_user, public_id):
    role = request.args.get("role")
    if not current_user.is_admin:
        return jsonify({'message' : 'Cannot perform that function', 'success' : False}), 406

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found', 'success' : False})

    if user.email_verified == True:
        if role == "admin":
            user.is_admin = True
            user.is_staff = True
            db.session.commit()
            return jsonify({'message' : 'The user has been promoted to admin', 'success' : True})

        if role == "staff":
            user.is_staff = True
            db.session.commit()
            return jsonify({'message' : 'The user has been promoted to staff', 'success' : True})

        return jsonify({'message' : 'Role argument cannot be found', 'success' : True}), 406

    return jsonify({'message' : 'The user needs to have verified their email', 'success' : False}), 406

@user_api.route('/<public_id>', methods=['DELETE'])
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
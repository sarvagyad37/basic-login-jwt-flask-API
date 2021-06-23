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

misc_api = Blueprint('misc_api', __name__)

@misc_api.route('/login',  methods=['POST'])
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


@misc_api.route('/refresh', methods=['POST'])
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
        data = jwt.decode(access_token, os.environ['SECRET_KEY'])
        return jsonify({'message' : 'Access Token is still valid', 'success': False})

    except jwt.ExpiredSignatureError:
        try:
            refresh_token_data = jwt.decode(refresh_token, os.environ['SECRET_KEY'])

        except jwt.ExpiredSignatureError:
            return jsonify({'message' : 'Refresh Token is expired. login again', 'success': False}), 406

        except:
            return jsonify({'message' : 'Refresh Token is invalid', 'success': False})

        access_token_data = jwt.decode(access_token, os.environ['SECRET_KEY'], options={"verify_exp" : False})

        if refresh_token_data['refreshtokenmatchid'] == access_token_data['tokenmatchid']:
            list_of_tokens = create_tokens(refresh_token_data['username'])

            token = list_of_tokens[0]
            refresh_token = list_of_tokens[1]

            return jsonify({'token' : token.decode('UTF-8'), 'refresh_token' : refresh_token.decode('UTF-8'), 'success': True})
        
        return jsonify({'message' : 'Tokens do not match', 'success': False})
    
    except:
        return jsonify({'message' : 'Invalid tokens', 'success': False})

@misc_api.route('/confirm')
def confirm_email():
    token = request.args.get("token")
    try: 
        data = jwt.decode(token, os.environ['SECRET_KEY'])
        current_user = User.query.filter_by(public_id=data['public_id']).first()

        current_user.email_verified = True
        db.session.commit()
        print(vars(current_user))

        return jsonify({'message' : 'email verified', 'email_verified_from_db': current_user.email_verfied, 'success': True})

    except jwt.ExpiredSignatureError:
        return jsonify({'message' : 'Token is expired!', 'expired' : True}), 403

    except:
        return jsonify({'message' : 'Token is invalid!'}), 401
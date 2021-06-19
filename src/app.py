from flask import Flask, jsonify
from .config import app_config
from .models import db
from .views.UserView import user_api as user_blueprint
from .views.MiscView import misc_api as misc_blueprint

#from .views.BlogpostView import blogpost_api as blogpost_blueprint

def create_app(env_name):

    app = Flask(__name__)

    app.config.from_object(app_config[env_name])

    db.init_app(app)

    app.register_blueprint(misc_blueprint, url_prefix='/api/v1/')
    app.register_blueprint(user_blueprint, url_prefix='/api/v1/users')
    #app.register_blueprint(blogpost_blueprint, url_prefix='/api/v1/blogposts')

    @app.route('/', methods=['GET'])
    def index():
        return jsonify({'message': 'lol xd'})

    return app

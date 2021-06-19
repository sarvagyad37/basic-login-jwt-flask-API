import os

class Development(object):
    """
    Development environment configuration
    """
    DEBUG = True
    TESTING = False
    SQLALCHEMY_TRACK_MODIFICATIONS=False
    SECRET_KEY = os.environ['SECRET_KEY']
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']

class Production(object):
    """
    Production environment configurations
    """
    uri = os.environ['DATABASE_URL']
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)

    DEBUG = False
    TESTING = False
    SQLALCHEMY_TRACK_MODIFICATIONS=False
    SQLALCHEMY_DATABASE_URI = uri
    SECRET_KEY = os.environ['SECRET_KEY']

app_config = {
    'development': Development,
    'production': Production
}
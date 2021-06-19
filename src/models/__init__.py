from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from .BlogpostModel import BlogpostModel
from .UserModel import User
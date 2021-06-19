import os

from src.app import create_app

env_name = os.environ['FLASK_ENV']

app = create_app(env_name)

if __name__ == '__main__':
    # run app
    app.run()
from flask import Flask,session,abort
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
import os

db = SQLAlchemy()
DB_NAME = "appdata.db"

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()

    return wrapper

def create_app():
    app = Flask(__name__)
    app.secret_key = 'rfgdrsgersgdgr rfgrdsgsrgrse'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    db.init_app(app)

    from show import show
    from route import route

    app.register_blueprint(show, url_prefix='/')
    app.register_blueprint(route, url_prefix='/')

    from models import User

    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'show.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app


def create_database(app):
    if not path.exists('website/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')



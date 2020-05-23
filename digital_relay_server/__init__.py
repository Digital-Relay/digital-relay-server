from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_security import MongoEngineUserDatastore, Security

from digital_relay_server.api.security import ExtendedRegisterForm, ExtendedConfirmRegisterForm
from digital_relay_server.db import db, User, Role

app = Flask(__name__)
app.config.from_pyfile('config/config.py')
config = app.config
logger = app.logger
CORS(app)
jwt = JWTManager(app)
mail = Mail()

db.init_app(app)
mail.init_app(app)

# Setup Flask-Security
user_datastore = MongoEngineUserDatastore(db, User, Role)
security = Security(app, user_datastore, register_form=ExtendedRegisterForm,
                    confirm_register_form=ExtendedConfirmRegisterForm)


def authenticate(email, password):
    user = user_datastore.get_user(email)
    if user and user.verify_and_update_password(password):
        user.id = str(user.id)
        return user

    return None


@jwt.user_loader_callback_loader
def identity(jwt_identity):
    return user_datastore.get_user(jwt_identity)


# Create a user to test with
# @app.before_first_request
def create_user():
    user_datastore.create_user(email='matt@nobien.net', password='password')


from digital_relay_server.api.api import blueprint

app.register_blueprint(blueprint, url_prefix=config['API_URL_PREFIX'])

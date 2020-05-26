from flask import Flask, render_template
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_mail import Mail, Message
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


def send_email_invites(recipients=None, author=None, team_name=None, team_link=None):
    with mail.connect() as connection:
        for recipient in recipients:
            print('sending invite')
            message = Message(subject=config['INVITE_SUBJECT'], recipients=[recipient])
            message.html = render_template('invite.html', author=author, team_name=team_name, team_link=team_link)

            connection.send(message)


from digital_relay_server.api.api import blueprint

app.register_blueprint(blueprint, url_prefix=config['API_URL_PREFIX'])

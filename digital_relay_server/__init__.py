from flask import Flask, request
from flask_jwt import JWT
from flask_mongoengine import MongoEngine
from flask_security import RoleMixin, UserMixin, MongoEngineUserDatastore, Security

app = Flask(__name__)
app.config.from_pyfile('config/config.py')
config = app.config
logger = app.logger

db = MongoEngine(app)


# noinspection PyUnresolvedReferences
class Role(db.Document, RoleMixin):
    name = db.StringField(max_length=80, unique=True)
    description = db.StringField(max_length=255)


# noinspection PyUnresolvedReferences
class User(db.Document, UserMixin):
    email = db.StringField(max_length=255)
    password = db.StringField(max_length=255)
    active = db.BooleanField(default=True)
    confirmed_at = db.DateTimeField()
    roles = db.ListField(db.ReferenceField(Role), default=[])


def authenticate(username, password):
    user = user_datastore.get_user(username)
    if user and user.verify_and_update_password(password):
        user.id = str(user.id)
        return user


def identity(payload):
    user_id = payload['identity']
    return user_datastore.get_user(user_id)


# Setup Flask-Security
user_datastore = MongoEngineUserDatastore(db, User, Role)
security = Security(app, user_datastore)

jwt = JWT(app, authenticate, identity)


# Create a user to test with
@app.before_first_request
def create_user():
    user_datastore.create_user(email='matt@nobien.net', password='password')


from digital_relay_server.api import api


def register_blueprints(app):
    app.register_blueprint(api.blueprint, url_prefix='/api')


register_blueprints(app)


@app.route('/authtest', methods=['POST'])
def authenticatetest():
    req = request.json
    username = req['email']
    password = req['password']
    user = user_datastore.get_user(username)
    print(user)
    if user and user.verify_and_update_password(password):
        return dict(user)

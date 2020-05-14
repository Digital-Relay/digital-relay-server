from flask import Blueprint
from flask_jwt import jwt_required, current_identity
from flask_restx import Resource, Api

blueprint = Blueprint('api', __name__)
api = Api(app=blueprint, title="Digital Relay API", doc="/documentation")

ns_auth = api.namespace('Auth', path='/auth', description='Auth endpoints')


# Views
@ns_auth.route('/hello')
class HelloWorld(Resource):

    @jwt_required()
    def get(self):
        return {'hello': current_identity.email}


@ns_auth.route('/hello2')
class HelloWorld2(Resource):
    def get(self):
        return {'hello': 'errgrtgh'}

from flask import Blueprint
from flask_jwt import jwt_required, current_identity
from flask_restx import Resource, Api, fields

from digital_relay_server.api.models import models
from digital_relay_server.api.security import authorizations

blueprint = Blueprint('api', __name__)
api = Api(app=blueprint, title="DXC RUN 4U API", doc="/documentation")

ns_auth = api.namespace('Auth', path='/auth', description='Security endpoints')
auth_header_parser = api.parser()
auth_header_parser.add_argument('Authorization', location='headers', required=True,
                                help='JWT auth token, format: JWT <access_token>', default='JWT <access_token>')

user_login = ns_auth.model('Login request', models['user_login_model'])
user_register = ns_auth.model('Register request', models['user_register_model'])
user = ns_auth.model('User model', models['user_model'])
jwt_response = ns_auth.model('JWT response', models['jwt_response_model'])
jwt_unauthorized = ns_auth.model('Unauthorized response', models['jwt_unauthorized_model'])
security_bad_request = ns_auth.model('Bad security response', models['registration_error_keys_model'])
response_meta = ns_auth.model('Response metadata', {'code': fields.Integer})
registration_error_keys = ns_auth.model('Registration error keys', models['registration_error_keys_model'])
registration_response_body = ns_auth.model('Registration response body', {'user': fields.Nested(user),
                                                                          'errors': fields.Nested(
                                                                              registration_error_keys)})
registration_response = ns_auth.model('Registration response', {'meta': fields.Nested(response_meta),
                                                                'response': fields.Nested(registration_response_body)})


@ns_auth.route('')
class Login(Resource):
    @ns_auth.expect(user_login)
    @ns_auth.response(code=200, description='Login successful', model=jwt_response)
    @ns_auth.response(code=401, description='Invalid credentials', model=jwt_unauthorized)
    def post(self):
        """Log in as an existing user"""
        # do nothing, auth is handled by flask-JWT endpoint, this is only for documentation
        pass


@ns_auth.route('/register')
class Register(Resource):
    @ns_auth.expect(user_register)
    @ns_auth.response(code=200, description='Registration successful', model=user)
    @ns_auth.response(code=400, description='Request invalid', model=registration_response)
    def post(self):
        """Register a new user"""
        # do nothing, registering is handled by flask-security endpoint, this is only for documentation
        pass


@ns_auth.route('/hello')
class HelloWorld(Resource):

    @jwt_required()
    @ns_auth.doc(security=authorizations)
    @ns_auth.expect(auth_header_parser)
    def get(self):
        return {'hello': current_identity.email}

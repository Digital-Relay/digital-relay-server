from bson import ObjectId
from bson.errors import InvalidId
from flask import Blueprint, request
from flask_jwt import jwt_required, current_identity
from flask_restx import Resource, Api, fields, marshal
from mongoengine import DoesNotExist, NotUniqueError

from digital_relay_server.api.models import models
from digital_relay_server.api.security import authorizations
from digital_relay_server.db import Team, User

blueprint = Blueprint('api', __name__)
api = Api(app=blueprint, title="DXC RUN 4U API", doc="/documentation")

ns_auth = api.namespace('Auth', path='/auth', description='Security endpoints')
ns_teams = api.namespace('Teams', path='/teams', description='Team management endpoints')

auth_header_parser = api.parser()
auth_header_parser.add_argument('Authorization', location='headers', required=True,
                                help='JWT auth token, format: JWT <access_token>', default='JWT <access_token>')

user_login = ns_auth.model('Login request', models['user_login_model'])
user_register = ns_auth.model('Register request', models['user_register_model'])
user = ns_auth.model('User model', models['user_model'])
jwt_response = ns_auth.model('JWT response', models['jwt_response_model'])
error = ns_auth.model('Error response', models['error_model'])
security_bad_request = ns_auth.model('Bad security response', models['registration_error_keys_model'])
response_meta = ns_auth.model('Response metadata', {'code': fields.Integer})
registration_error_keys = ns_auth.model('Registration error keys', models['registration_error_keys_model'])
registration_response_body = ns_auth.model('Registration response body', {'csrf_token': fields.String,
                                                                          'user': fields.Nested(user),
                                                                          'errors': fields.Nested(
                                                                              registration_error_keys)})
registration_response = ns_auth.model('Registration response', {'meta': fields.Nested(response_meta),
                                                                'response': fields.Nested(registration_response_body)})
team = ns_teams.model('Team model', models['team_model'])
team_list = ns_teams.model('Teams list', {'teams': fields.List(fields.Nested(team))})
user_list = ns_teams.model('User list', {'users': fields.List(fields.Nested(user))})


@ns_auth.route('')
class Login(Resource):
    @ns_auth.expect(user_login)
    @ns_auth.response(code=200, description='Login successful', model=jwt_response)
    @ns_auth.response(code=401, description='Invalid credentials', model=error)
    def post(self):
        """Log in as an existing user"""
        # do nothing, auth is handled by flask-JWT endpoint, this is only for documentation
        pass


@ns_auth.route('/register')
class Register(Resource):
    @ns_auth.expect(user_register)
    @ns_auth.response(code=200, description='Registration successful', model=registration_response)
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


@ns_teams.route('')
class Teams(Resource):
    @jwt_required()
    @ns_teams.doc(security=authorizations)
    @ns_teams.expect(auth_header_parser, team)
    @ns_teams.response(code=200, description='Team creation successful', model=team)
    @ns_teams.response(code=400, description='Bad request', model=error)
    @ns_teams.response(code=409, description='Team already exists', model=error)
    def post(self):
        """Create a new team"""
        data = request.json
        try:
            new_team = Team(name=data['name'], members=data['members'] + [current_identity.email])
        except KeyError as e:
            return marshal({"description": f'{e.args[0]} is a required parameter',
                            "error": 'Missing required parameter',
                            "status_code": 400}, error), 400
        try:
            response = new_team.save()
            return marshal(response, team), 200
        except NotUniqueError:
            return marshal({"description": f'Team named {new_team.name} already exists',
                            "error": 'Invalid team name',
                            "status_code": 409}, error), 409

    @jwt_required()
    @ns_teams.doc(security=authorizations)
    @ns_teams.expect(auth_header_parser)
    @ns_teams.response(code=200, description='OK', model=team_list)
    @ns_teams.response(code=401, description='Unauthorized', model=error)
    def get(self):
        """Retrieve all teams that the current user belongs to"""
        teams = Team.objects(members=current_identity.email)
        return marshal({'teams': teams}, team_list), 200


# noinspection PyUnresolvedReferences
@ns_teams.route('/<team_id>')
class TeamResource(Resource):
    @ns_teams.response(code=200, description='OK', model=team)
    @ns_teams.response(code=400, description='Invalid ID', model=error)
    @ns_teams.response(code=404, description='Team not found', model=error)
    def get(self, team_id):
        """Retrieve team information"""
        try:
            response = Team.objects.get(id=ObjectId(team_id))
            return marshal(response, team), 200
        except InvalidId:
            return marshal({"description": f'{team_id} is not a valid ObjectID',
                            "error": 'Invalid ID',
                            "status_code": 400}, error), 400
        except DoesNotExist:
            return marshal({"description": f'Team with team ID {team_id} does not exist',
                            "error": 'Not found',
                            "status_code": 404}, error), 404


# noinspection PyUnresolvedReferences
@ns_teams.route('/<team_id>/users')
class TeamMembers(Resource):
    @ns_teams.response(code=200, description='OK', model=team)
    @ns_teams.response(code=400, description='Invalid ID', model=error)
    @ns_teams.response(code=404, description='Team not found', model=error)
    def get(self, team_id):
        """Retrieve team members as user objects"""
        try:
            team = Team.objects.get(id=ObjectId(team_id))
            emails = team.members
            users = list(User.objects(email__in=emails))
            for user in users:
                if user.email in emails:
                    emails.remove(user.email)

            for email in emails:
                users.append(User(id='null', name='null', email=email))
            return marshal({'users': users}, user_list), 200
        except InvalidId:
            return marshal({"description": f'{team_id} is not a valid ObjectID',
                            "error": 'Invalid ID',
                            "status_code": 400}, error), 400
        except DoesNotExist:
            return marshal({"description": f'Team with team ID {team_id} does not exist',
                            "error": 'Not found',
                            "status_code": 404}, error), 404

from bson import ObjectId
from bson.errors import InvalidId
from flask import Blueprint, request
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, \
    current_user, jwt_refresh_token_required
from flask_restx import Resource, Api, marshal
from mongoengine import DoesNotExist, NotUniqueError

from digital_relay_server import authenticate
from digital_relay_server.api.models import Models
from digital_relay_server.api.security import authorizations, expiry_date_from_token
from digital_relay_server.db import Team, User

blueprint = Blueprint('api', __name__)
api = Api(app=blueprint, title="DXC RUN 4U API", doc="/documentation")

ns_auth = api.namespace('Auth', path='/auth', description='Security endpoints')
ns_teams = api.namespace('Teams', path='/teams', description='Team management endpoints')
team_id_in_route = '<team_id>'

auth_header_jwt_parser = api.parser()
auth_header_jwt_parser.add_argument('Authorization', location='headers', required=True,
                                    help='JWT auth token, format: JWT <access_token>', default='JWT <access_token>')

auth_header_jwt_refresh_parser = api.parser()
auth_header_jwt_refresh_parser.add_argument('Authorization', location='headers', required=True,
                                            help='JWT refresh token, format: JWT <refresh_token>',
                                            default='JWT <refresh_token>')

models = Models(ns_auth=ns_auth, ns_teams=ns_teams)


@ns_auth.route('')
class Login(Resource):
    @ns_auth.expect(models.user_login)
    @ns_auth.response(code=200, description='Login successful', model=models.jwt_response)
    @ns_auth.response(code=401, description='Invalid credentials', model=models.error)
    def post(self):
        """Login as existing user"""
        if not request.is_json:
            return marshal({"msg": "Missing JSON in request"}, models.error), 400

        try:
            email = request.json['email']
            password = request.json['password']
        except KeyError as e:
            return marshal({"msg": f'{e.args[0]} is a required parameter'}, models.error), 400

        logged_in_user = authenticate(email, password)
        if not logged_in_user:
            return marshal({"msg": 'Invalid credentials.'}, models.error), 401

        if not logged_in_user.confirmed_at:
            return marshal({"msg": 'Email not confirmed'}, models.error), 401

        access_token = create_access_token(identity=logged_in_user.email, fresh=True)
        refresh_token = create_refresh_token(identity=logged_in_user.email)
        return marshal({'access_token': access_token,
                        'refresh_token': refresh_token,
                        'expires_at': expiry_date_from_token(access_token),
                        'user': logged_in_user}, models.jwt_response), 200

    @jwt_required
    @ns_auth.doc(security=authorizations)
    @ns_auth.expect(auth_header_jwt_parser)
    @ns_auth.response(code=200, description='OK', model=models.user)
    @ns_auth.response(code=401, description='Invalid credentials', model=models.error)
    def get(self):
        """Retrieve current user's info"""
        return marshal(current_user, models.user), 200


@ns_auth.route('/register')
class Register(Resource):
    @ns_auth.expect(models.user_register)
    @ns_auth.response(code=200, description='Registration successful', model=models.registration_response)
    @ns_auth.response(code=400, description='Request invalid', model=models.registration_response)
    def post(self):
        """Register a new user"""
        # do nothing, registering is handled by flask-security endpoint, this is only for documentation
        pass


@ns_auth.route('/refresh_token')
class TokenRefresh(Resource):
    @jwt_refresh_token_required
    @ns_auth.doc(security=authorizations)
    @ns_auth.expect(auth_header_jwt_refresh_parser)
    @ns_auth.response(code=200, description='Token refresh successful', model=models.jwt_response)
    @ns_auth.response(code=401, description='Invalid token', model=models.error)
    @ns_auth.response(code=422, description='Invalid token', model=models.error)
    def get(self):
        """Get a new access token"""
        access_token = create_access_token(current_user.email)
        return marshal({'access_token': access_token,
                        'refresh_token': None,
                        'expires_at': expiry_date_from_token(access_token),
                        'user': current_user}, models.jwt_response), 200


@ns_auth.route('/hello')
class HelloWorld(Resource):

    @jwt_required
    @ns_auth.doc(security=authorizations)
    @ns_auth.expect(auth_header_jwt_parser)
    def get(self):
        return {'hello': current_user.email}


@ns_teams.route('')
class Teams(Resource):
    @jwt_required
    @ns_teams.doc(security=authorizations)
    @ns_teams.expect(auth_header_jwt_parser, models.team)
    @ns_teams.response(code=200, description='Team creation successful', model=models.team)
    @ns_teams.response(code=400, description='Bad request', model=models.error)
    @ns_teams.response(code=401, description='Unauthorized', model=models.error)
    @ns_teams.response(code=409, description='Team already exists', model=models.error)
    def post(self):
        """Create a new team"""
        data = request.json
        try:
            new_team = Team(name=data['name'], members=data['members'] + [current_user.email])
        except KeyError as e:
            return marshal({"msg": f'{e.args[0]} is a required parameter'}, models.error), 400

        new_team.set_default_stages()
        try:
            if new_team.check_stages_validity(data['stages']):
                new_team.stages = data['stages']
            else:
                return marshal({"msg": 'Stage count mismatch'}, models.error), 400
        except ValueError as e:
            return marshal({"msg": f'{e.args[0]} is not a member of this team'}, models.error), 400
        except KeyError:
            pass

        try:
            response = new_team.save()
            return marshal(response, models.team), 200
        except NotUniqueError:
            return marshal({"msg": f'Team named {new_team.name} already exists'}, models.error), 409

    @jwt_required
    @ns_teams.doc(security=authorizations)
    @ns_teams.expect(auth_header_jwt_parser)
    @ns_teams.response(code=200, description='OK', model=models.team_list)
    @ns_teams.response(code=401, description='Unauthorized', model=models.error)
    def get(self):
        """Retrieve all teams that the current user belongs to"""
        teams = Team.objects(members=current_user.email)
        return marshal({'teams': teams}, models.team_list), 200


@ns_teams.route(f'/{team_id_in_route}')
class TeamResource(Resource):
    @ns_teams.response(code=200, description='OK', model=models.team)
    @ns_teams.response(code=400, description='Invalid ID', model=models.error)
    @ns_teams.response(code=404, description='Team not found', model=models.error)
    def get(self, team_id):
        """Retrieve team information"""
        try:
            response = Team.objects.get(id=ObjectId(team_id))
            return marshal(response, models.team), 200
        except InvalidId:
            return marshal({"msg": f'{team_id} is not a valid ObjectID'}, models.error), 400
        except DoesNotExist:
            return marshal({"msg": f'Team with team ID {team_id} does not exist'}, models.error), 404

    @jwt_required
    @ns_teams.doc(security=authorizations)
    @ns_teams.expect(auth_header_jwt_parser, models.team)
    @ns_teams.response(code=200, description='Team update successful', model=models.team)
    @ns_teams.response(code=400, description='Bad request', model=models.error)
    @ns_teams.response(code=401, description='Unauthorized', model=models.error)
    @ns_teams.response(code=404, description='Team not found', model=models.error)
    @ns_teams.response(code=409, description='Team name already exists', model=models.error)
    def post(self, team_id):
        """Update team information"""
        data = request.json
        if team_id != data['id']:
            return marshal({"msg": 'Team IDs in URL and request do not match'}, models.error), 400
        try:
            team = Team.objects.get(id=ObjectId(team_id))
        except InvalidId:
            return marshal({"msg": f'{team_id} is not a valid ObjectID'}, models.error), 400
        except DoesNotExist:
            return marshal({"msg": f'Team with team ID {team_id} does not exist'}, models.error), 404
        team.name = data['name']
        team.members = data['members']
        try:
            if team.check_stages_validity(data['stages']):
                team.stages = data['stages']
            else:
                return marshal({"msg": 'Stage count mismatch'}, models.error), 400
        except ValueError as e:
            return marshal({"msg": f'{e.args[0]} is not a member of this team'}, models.error), 400
        except KeyError:
            pass
        if not team.stages:
            team.set_default_stages()
        try:
            response = team.save()
            return marshal(response, models.team), 200
        except NotUniqueError:
            return marshal({"msg": f'Team named {team.name} already exists'}, models.error), 409


@ns_teams.route(f'/{team_id_in_route}/users')
class TeamMembers(Resource):
    @ns_teams.response(code=200, description='OK', model=models.team)
    @ns_teams.response(code=400, description='Invalid ID', model=models.error)
    @ns_teams.response(code=404, description='Team not found', model=models.error)
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
            return marshal({'users': users}, models.user_list), 200
        except InvalidId:
            return marshal({"msg": f'{team_id} is not a valid ObjectID'}, models.error), 400
        except DoesNotExist:
            return marshal({"msg": f'Team with team ID {team_id} does not exist'}, models.error), 404

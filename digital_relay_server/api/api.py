import json

import pywebpush
from bson import ObjectId
from bson.errors import InvalidId
from flask import Blueprint, request, render_template
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, \
    current_user, jwt_refresh_token_required
from flask_restx import Resource, Api, marshal
from mongoengine import DoesNotExist, NotUniqueError, ValidationError

from digital_relay_server import authenticate, send_email_invites, send_push_notifications
from digital_relay_server.api.models import Models, PushNotificationAction, PushNotification, \
    PushNotificationData
from digital_relay_server.api.security import authorizations, expiry_date_from_token
from digital_relay_server.config.config import VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, API_VERSION, VAPID_CLAIMS_SUB, \
    PUSH_HEADERS
from digital_relay_server.db import Team, User

blueprint = Blueprint('api', __name__)
api = Api(app=blueprint, title="DXC RUN 4U API", doc="/documentation", version=API_VERSION)

ns_auth = api.namespace('Auth', path='/auth', description='Security endpoints')
ns_teams = api.namespace('Teams', path='/teams', description='Team management endpoints')
ns_users = api.namespace('Users', path='/users', description='User management endpoints')
team_id_in_route = '<team_id>'

auth_header_jwt_parser = api.parser()
auth_header_jwt_parser.add_argument('Authorization', location='headers', required=True,
                                    help='JWT auth token, format: JWT <access_token>', default='JWT <access_token>')

auth_header_jwt_refresh_parser = api.parser()
auth_header_jwt_refresh_parser.add_argument('Authorization', location='headers', required=True,
                                            help='JWT refresh token, format: JWT <refresh_token>',
                                            default='JWT <refresh_token>')

models = Models(ns_auth=ns_auth, ns_teams=ns_teams)


def json_payload_required(func):
    def check(*args, **kwargs):
        if not request.is_json:
            return marshal({"msg": "Missing JSON in request"}, models.error), 400
        return func(*args, **kwargs)

    check.__doc__ = func.__doc__
    check.__name__ = func.__name__
    return check


@ns_auth.route('')
class Login(Resource):
    @ns_auth.expect(models.user_login)
    @ns_auth.response(code=200, description='Login successful', model=models.jwt_response)
    @ns_auth.response(code=401, description='Invalid credentials', model=models.error)
    @json_payload_required
    def post(self):
        """Login as existing user"""
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


@ns_auth.route('/register')
class Register(Resource):
    @ns_auth.expect(models.user_register)
    @ns_auth.response(code=200, description='Registration successful', model=models.registration_response)
    @ns_auth.response(code=400, description='Request invalid', model=models.registration_response)
    def post(self):
        """Register a new user"""
        # do nothing, registering is handled by flask-security endpoint, this is only for documentation
        pass


@ns_auth.route('/reset')
class Reset(Resource):
    @ns_auth.expect(models.user_reset)
    @ns_auth.response(code=200, description='Registration successful', model=models.registration_response)
    @ns_auth.response(code=400, description='Request invalid', model=models.registration_response)
    def post(self):
        """Request user password reset"""
        # do nothing, password reset is handled by flask-security endpoint, this is only for documentation
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


@ns_auth.route('/push')
class PushResource(Resource):
    @ns_auth.response(code=200, description='OK', model=models.vapid_public_key)
    def get(self):
        """Get VAPID public key"""
        return marshal({'public_key': VAPID_PUBLIC_KEY}, models.vapid_public_key), 200

    @jwt_required
    @ns_auth.doc(security=authorizations)
    @ns_auth.expect(auth_header_jwt_parser, models.push_subscription)
    @ns_auth.response(code=200, description='Push subscription saved')
    @ns_auth.response(code=204, description='Push subscription already registered')
    @ns_auth.response(code=400, description='Bad request', model=models.error)
    @ns_auth.response(code=401, description='Unauthorized', model=models.error)
    @json_payload_required
    def post(self):
        """Add new push subscription to current user"""
        data = request.json
        if current_user.push_subscriptions.count(data) == 0:
            current_user.push_subscriptions.append(data)
            push_message = PushNotification(title='Upozornenia fungujú!',
                                            body='Ďakujeme za povolenie upozornení.').to_dict()
            try:
                pywebpush.webpush(subscription_info=data,
                                  data=json.dumps(push_message),
                                  vapid_private_key=VAPID_PRIVATE_KEY,
                                  vapid_claims={'sub': VAPID_CLAIMS_SUB},
                                  headers=PUSH_HEADERS)
            except pywebpush.WebPushException as e:
                return marshal({'msg': e.message}, models.error), 400
        else:
            return 'Push subscription already registered', 204
        current_user.save()
        return 'OK', 200


@ns_auth.route('/hello')
class HelloWorld(Resource):

    @jwt_required
    @ns_auth.doc(security=authorizations)
    @ns_auth.expect(auth_header_jwt_parser)
    def get(self):
        return {'hello': current_user.email}


@ns_teams.route('/all')
class AllTeams(Resource):
    @ns_teams.response(code=200, description='OK', model=models.team_list)
    def get(self):
        """Retrieve all teams public information (no stages info)"""
        teams = list(Team.objects())
        response = []
        for team in teams:
            response.append(team.public_info)
        return marshal({'teams': response}, models.team_list), 200


@ns_teams.route('')
class Teams(Resource):
    @jwt_required
    @ns_teams.doc(security=authorizations)
    @ns_teams.expect(auth_header_jwt_parser, models.team)
    @ns_teams.response(code=200, description='Team creation successful', model=models.team)
    @ns_teams.response(code=400, description='Bad request', model=models.error)
    @ns_teams.response(code=401, description='Unauthorized', model=models.error)
    @ns_teams.response(code=409, description='Team already exists', model=models.error)
    @json_payload_required
    def post(self):
        """Create a new team"""
        data = request.json
        try:
            data['members'] = list(set(data['members']))
            new_team = Team(name=data['name'], _members=data['members'] + [current_user.email])
        except KeyError as e:
            return marshal({"msg": f'{e.args[0]} is a required parameter'}, models.error), 400

        new_team.set_default_stages()
        try:
            new_team.stages = data['stages']
        except IndexError:
            return marshal({"msg": 'Stage count mismatch'}, models.error), 400
        except ValueError as e:
            return marshal({"msg": f'{e.args[0]} is not a member of this team'}, models.error), 400
        except KeyError:
            pass

        try:
            new_team.donation = max(data['donation'], 0)
        except KeyError:
            pass

        try:
            new_team.start = max(data['start'], 0)
        except KeyError:
            pass

        try:
            response = new_team.save()
            send_email_invites(recipients=data['members'], author=current_user.name, team_name=new_team.name,
                               team_link=new_team.url)
            return marshal(response, models.team), 200
        except NotUniqueError:
            return marshal({"msg": f'Team named {new_team.name} already exists'}, models.error), 409
        except ValidationError as e:
            return marshal({"msg": f'Invalid parameter: {e.message}'}, models.error), 400

    @jwt_required
    @ns_teams.doc(security=authorizations)
    @ns_teams.expect(auth_header_jwt_parser)
    @ns_teams.response(code=200, description='OK', model=models.team_list)
    @ns_teams.response(code=401, description='Unauthorized', model=models.error)
    def get(self):
        """Retrieve all teams that the current user belongs to"""
        teams = Team.objects(_members=current_user.email)
        return marshal({'teams': teams}, models.team_list), 200


def update_stages(team, stages):
    for stage_dict in stages:
        if stage_dict['email'] not in team.members:
            raise ValueError(stage_dict['email'])
        found = False
        for stage in team.stages:
            if stage.index == stage_dict["index"]:
                stage.load_values(stage_dict=stage_dict)
                found = True
                break
        if not found:
            return False
    return True


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
    @json_payload_required
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
        new_members = []
        try:
            if not data['members']:
                data['members'] = [current_user.email]

            if current_user.email not in data['members']:
                data['members'].append(current_user.email)

            data['members'] = list(set(data['members']))
            new_members = team.new_members(data['members'])
            team.members = data['members']
        except KeyError:
            pass
        try:
            if not update_stages(team=team, stages=data['stages']):
                return marshal({"msg": 'Invalid stage index'}, models.error), 400
        except IndexError:
            return marshal({"msg": 'Stage count mismatch'}, models.error), 400
        except ValueError as e:
            return marshal({"msg": f'{e.args[0]} is not a member of this team'}, models.error), 400
        except KeyError:
            pass
        if not team.stages:
            team.set_default_stages()

        try:
            team.donation = max(data['donation'], 0)
        except KeyError:
            pass

        try:
            team.start = max(data['start'], 0)
        except KeyError:
            pass

        try:
            send_email_invites(new_members, current_user.name, team.name, team.url)
            response = team.save()
            return marshal(response, models.team), 200
        except NotUniqueError:
            return marshal({"msg": f'Team named {team.name} already exists'}, models.error), 409
        except ValidationError as e:
            return marshal({"msg": f'Invalid parameter: {e.message}'}, models.error), 400


@ns_teams.route(f'/{team_id_in_route}/users')
class TeamMembers(Resource):
    @ns_teams.doc(security=authorizations)
    @ns_teams.expect(auth_header_jwt_parser)
    @ns_teams.response(code=200, description='OK', model=models.user_list)
    @ns_teams.response(code=400, description='Invalid ID', model=models.error)
    @ns_teams.response(code=403, description='Team not found', model=models.error)
    @ns_teams.response(code=404, description='Team not found', model=models.error)
    @jwt_required
    def get(self, team_id):
        """Retrieve team members as user objects"""
        try:
            team = Team.objects.get(id=ObjectId(team_id))
            if current_user.email not in team.members:
                return marshal({"msg": f'You cannot access this team'}, models.error), 403
            users = team.members_as_user_objects()
            return marshal({'users': users}, models.user_list), 200
        except InvalidId:
            return marshal({"msg": f'{team_id} is not a valid ObjectID'}, models.error), 400
        except DoesNotExist:
            return marshal({"msg": f'Team with team ID {team_id} does not exist'}, models.error), 404

    @jwt_required
    @ns_teams.doc(security=authorizations, description='Add new members to the team and send them e-mail invites')
    @ns_teams.expect(auth_header_jwt_parser, models.add_members_request)
    @ns_teams.response(code=200, description='OK', model=models.user_list)
    @ns_teams.response(code=400, description='Invalid ID', model=models.error)
    @ns_teams.response(code=404, description='Team not found', model=models.error)
    @json_payload_required
    def post(self, team_id):
        """Add users to team"""
        data = request.json
        try:
            team = Team.objects.get(id=ObjectId(team_id))
        except InvalidId:
            return marshal({"msg": f'{team_id} is not a valid ObjectID'}, models.error), 400
        except DoesNotExist:
            return marshal({"msg": f'Team with team ID {team_id} does not exist'}, models.error), 404

        new_members = team.new_members(data['members'])
        send_email_invites(recipients=new_members, author=current_user.name, team_name=team.name, team_link=team.url)
        team.save()
        users = team.members_as_user_objects()
        return marshal({'users': users}, models.user_list), 200


@ns_teams.route(f'/{team_id_in_route}/stages')
class Stages(Resource):
    @jwt_required
    @ns_auth.doc(security=authorizations)
    @ns_teams.expect(auth_header_jwt_parser, models.edit_stages_request)
    @ns_teams.response(code=200, description='OK', model=models.team)
    @ns_teams.response(code=400, description='Invalid ID', model=models.error)
    @ns_teams.response(code=404, description='Team not found', model=models.error)
    @json_payload_required
    def post(self, team_id):
        """Edit stages assignment"""
        data = request.json
        try:
            team = Team.objects.get(id=ObjectId(team_id))
        except InvalidId:
            return marshal({"msg": f'{team_id} is not a valid ObjectID'}, models.error), 400
        except DoesNotExist:
            return marshal({"msg": f'Team with team ID {team_id} does not exist'}, models.error), 404
        active_stage = team.active_stage
        try:
            if not update_stages(team=team, stages=data['stages']):
                return marshal({"msg": 'Invalid stage index'}, models.error), 400
        except ValueError as e:
            return marshal({"msg": f'{e.args[0]} is not a member of this team'}, models.error), 400
        except KeyError as e:
            return marshal({"msg": f'{e.args[0]} is a required parameter'}, models.error), 400
        except IndexError:
            return marshal({"msg": 'Stage index out of range'}, models.error), 400
        new_active_stage = team.active_stage
        if active_stage != new_active_stage:
            finisher = active_stage.email
            try:
                finisher_user = User.objects.get(email=finisher)
            except DoesNotExist:
                finisher_user = User(name=finisher)
            next = None
            if new_active_stage:
                next = new_active_stage.email

            stage_ended_recipients = team.members.copy()
            stage_ended_recipients.remove(finisher)
            send_push_notifications(list(User.objects(email__in=stage_ended_recipients)),
                                    PushNotification(title='Úsek ukončený',
                                                     body=f'{finisher_user.name} práve dobehol úsek č. {active_stage.index + 1}',
                                                     actions=PushNotificationAction.quick_actions(team_page=True),
                                                     data=PushNotificationData(team_id=team_id)))
            if next:
                next_push_notification = PushNotification(title='Štart!',
                                                          body=f'Vyrážate na úsek {new_active_stage.index + 1}!',
                                                          data=PushNotificationData(team_id=team_id),
                                                          actions=PushNotificationAction.quick_actions(True, True))
                send_push_notifications(list(User.objects(email=next)), next_push_notification)
        team.save()
        return marshal(team, models.team), 200


@ns_teams.route(f'/{team_id_in_route}/accept_relay')
class AcceptRelay(Resource):
    @jwt_required
    @ns_auth.doc(security=authorizations)
    @ns_teams.expect(auth_header_jwt_parser)
    @ns_teams.response(code=200, description='OK')
    @ns_teams.response(code=400, description='Invalid ID', model=models.error)
    @ns_teams.response(code=404, description='Team not found', model=models.error)
    def post(self, team_id):
        """Send push notifications about starting a stage to other team members"""
        try:
            team = Team.objects.get(id=ObjectId(team_id))
        except InvalidId:
            return marshal({"msg": f'{team_id} is not a valid ObjectID'}, models.error), 400
        except DoesNotExist:
            return marshal({"msg": f'Team with team ID {team_id} does not exist'}, models.error), 404

        active_stage = team.active_stage
        recipients_emails = team.members.copy()
        recipients_emails.remove(current_user.email)
        send_push_notifications(list(User.objects(email__in=recipients_emails)),
                                notification=PushNotification(title='Štafeta prevzatá',
                                body=f'{current_user.name} vybehol na úsek číslo {active_stage.index + 1}'))
        return 'OK', 200


@ns_users.route('')
class UserResource(Resource):
    @jwt_required
    @ns_users.doc(security=authorizations)
    @ns_users.expect(auth_header_jwt_parser)
    @ns_users.response(code=200, description='OK', model=models.user)
    @ns_users.response(code=401, description='Invalid credentials', model=models.error)
    def get(self):
        """Retrieve current user's info"""
        return marshal(current_user, models.user), 200

    @jwt_required
    @ns_users.doc(security=authorizations)
    @ns_users.expect(auth_header_jwt_parser, models.user)
    @ns_users.response(code=200, description='OK', model=models.user)
    @ns_users.response(code=400, description='Missing required parameter', model=models.error)
    @ns_users.response(code=401, description='Invalid credentials', model=models.error)
    @json_payload_required
    def post(self):
        """Update current user's info"""
        data = request.json
        try:
            current_user.name = data['name']
            current_user.tempo = data['tempo']
            current_user.save()
        except KeyError as e:
            return marshal({"msg": f'{e.args[0]} is a required parameter'}, models.error), 400
        return marshal(current_user, models.user), 200

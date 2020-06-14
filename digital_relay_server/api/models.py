import json

import jsons
from flask import jsonify
from flask_restx import fields, Namespace

from digital_relay_server.config.config import *


class PushNotificationData:
    def __init__(self, team_id=None, user_id=None, stage=None) -> None:
        self.userId = user_id
        self.teamId = team_id
        self.stage = stage


class PushNotificationAction:

    def __init__(self, action=None, title=None) -> None:
        self.action = action
        self.title = title


    @staticmethod
    def quick_actions(team_page=False, accept_relay=False):
        result = []
        if team_page:
            result.append(PushNotificationAction('team', 'Stránka tímu'))
        if accept_relay:
            result.append(PushNotificationAction('relay', 'Prebrať štafetu'))
        return result


class PushNotification:

    def __init__(self, title=None, body=None, icon=PUSH_NOTIFICATION_ICON, data=None, actions=None) -> None:
        if data is None:
            data = {}
        self.data = data
        if actions is None:
            actions = []
        self.actions = actions
        self.icon = icon
        self.body = body
        self.title = title

    def to_dict(self):
        return {"notification": jsons.dump(self)}


class Models:
    def __init__(self, ns_auth: Namespace, ns_teams: Namespace):
        user_register_model = {'email': fields.String(max_length=EMAIL_MAX_LENGTH, required=True),
                               'name': fields.String(max_length=NAME_MAX_LENGTH, required=True),
                               'tempo': fields.Integer(min=0, required=True, description='Runners tempo, in secs/km'),
                               'password': fields.String(max_length=PASSWORD_MAX_LENGTH, required=True)}
        user_reset_model = {'email': fields.String(max_length=EMAIL_MAX_LENGTH, required=True)}

        registration_error_keys = {}
        for key in user_register_model:
            registration_error_keys[key] = fields.List(fields.String, attribute=key)

        self.user_login = ns_auth.model('LoginRequest',
                                        {'email': fields.String(max_length=EMAIL_MAX_LENGTH, required=True),
                                         'password': fields.String(max_length=PASSWORD_MAX_LENGTH, required=True)})
        self.user_register = ns_auth.model('RegisterRequest', user_register_model)
        self.user_reset = ns_auth.model('PasswordResetRequest', user_reset_model)
        self.user = ns_auth.model('User', {'id': fields.String,
                                           'email': fields.String(max_length=EMAIL_MAX_LENGTH, required=True),
                                           'name': fields.String(max_length=NAME_MAX_LENGTH, required=True),
                                           'tempo': fields.Float(min=0, required=True)})
        self.jwt_response = ns_auth.model('JWTResponse', {'access_token': fields.String(required=True),
                                                          'refresh_token': fields.String,
                                                          'expires_at': fields.Integer(required=True),
                                                          'user': fields.Nested(self.user)})
        self.jwt_refresh_response = ns_auth.model('JWTRefreshResponse', {'access_token': fields.String(required=True),
                                                                         'expires_at': fields.DateTime(required=True)})
        self.error = ns_auth.model('ErrorResponse', {"msg": fields.String()})

        self.security_bad_request = ns_auth.model('BadSecurityResponse', registration_error_keys)
        self.response_meta = ns_auth.model('ResponseMetadata', {'code': fields.Integer})
        self.registration_error_keys = ns_auth.model('RegistrationErrorKeys', registration_error_keys)
        self.registration_response_body = ns_auth.model('RegistrationResponseBody', {'csrf_token': fields.String,
                                                                                     'user': fields.Nested(self.user),
                                                                                     'errors': fields.Nested(
                                                                                         self.registration_error_keys)})
        self.registration_response = ns_auth.model('RegistrationResponse', {'meta': fields.Nested(self.response_meta),
                                                                            'response': fields.Nested(
                                                                                self.registration_response_body)})
        self.stage = ns_teams.model(name='Stage',
                                    model={'index': fields.Integer(min=0, max=NUMBER_OF_STAGES - 1, required=True),
                                           'email': fields.String(max_length=EMAIL_MAX_LENGTH, required=True),
                                           'estimated_time': fields.Integer(min=0),
                                           'real_time': fields.Integer(min=0),
                                           'length': fields.Integer(min=0),
                                           'id': fields.String})
        self.team = ns_teams.model('Team', {'id': fields.String,
                                            'name': fields.String(max_length=TEAM_NAME_MAX_LENGTH, required=True),
                                            'donation': fields.Float(min=0),
                                            'start': fields.Integer(min=0, max=DAY_SECONDS,
                                                                    description="Team's starting time of day, in seconds since midnight"),
                                            'members': fields.List(fields.String(max_length=EMAIL_MAX_LENGTH),
                                                                   required=True),
                                            'stages': fields.List(fields.Nested(self.stage))})
        self.team_list = ns_teams.model('TeamsList', {'teams': fields.List(fields.Nested(self.team))})
        self.user_list = ns_teams.model('UserList', {'users': fields.List(fields.Nested(self.user))})
        self.edit_stages_request = ns_teams.model('EditStagesRequest',
                                                  {'stages': fields.List(fields.Nested(self.stage))})
        self.add_members_request = ns_teams.model('AddMembersRequest', {
            'members': fields.List(fields.String(max_length=EMAIL_MAX_LENGTH), required=True)})
        self.vapid_public_key = ns_auth.model('VAPIDKey', {'public_key': fields.String(required=True)})
        self.push_subscription_keys = ns_auth.model('PushSubscriptionKeys', {'p256dh': fields.String(),
                                                                             'auth': fields.String()})
        self.push_subscription = ns_auth.model('PushSubscription', {'endpoint': fields.String(required=True),
                                                                    'expiration_time': fields.Integer(),
                                                                    'keys': fields.Nested(self.push_subscription_keys)})

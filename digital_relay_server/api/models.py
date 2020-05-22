from flask_restx import fields, Namespace

from digital_relay_server.config.config import *


class Models:
    user_login = None
    user_register = None
    user = None
    jwt_response = None
    error = None
    security_bad_request = None
    response_meta = None
    registration_error_keys = None
    registration_response_body = None
    registration_response = None
    team = None
    team_list = None
    user_list = None

    def __init__(self, ns_auth: Namespace, ns_teams: Namespace):
        user_register_model = {'email': fields.String(max_length=EMAIL_MAX_LENGTH, required=True),
                               'name': fields.String(max_length=NAME_MAX_LENGTH, required=True),
                               'tempo': fields.Float(min=0, required=True),
                               'password': fields.String(max_length=PASSWORD_MAX_LENGTH, required=True)}

        registration_error_keys = {}
        for key in user_register_model:
            registration_error_keys[key] = fields.List(fields.String, attribute=key)

        self.user_login = ns_auth.model('LoginRequest',
                                        {'email': fields.String(max_length=EMAIL_MAX_LENGTH, required=True),
                                         'password': fields.String(max_length=PASSWORD_MAX_LENGTH, required=True)})
        self.user_register = ns_auth.model('RegisterRequest', user_register_model)
        self.user = ns_auth.model('User', {'id': fields.String,
                                           'email': fields.String(max_length=EMAIL_MAX_LENGTH, required=True),
                                           'name': fields.String(max_length=NAME_MAX_LENGTH, required=True),
                                           'tempo': fields.Float(min=0, required=True)})
        self.jwt_response = ns_auth.model('JWTResponse', {'access_token': fields.String,
                                                          'refresh_token': fields.String,
                                                          'expires_at': fields.DateTime,
                                                          'user': fields.Nested(self.user)})
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
        self.team = ns_teams.model('Team', {'id': fields.String,
                                            'name': fields.String(max_length=TEAM_NAME_MAX_LENGTH, required=True),
                                            # 'url_safe_name': fields.String(max_length=config["TEAM_URL_MAX_LENGTH"]),
                                            'members': fields.List(fields.String(max_length=EMAIL_MAX_LENGTH),
                                                                   required=True)})
        self.team_list = ns_teams.model('TeamsList', {'teams': fields.List(fields.Nested(self.team))})
        self.user_list = ns_teams.model('UserList', {'users': fields.List(fields.Nested(self.user))})

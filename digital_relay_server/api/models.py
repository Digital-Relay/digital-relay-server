from flask_restx import fields

models = {}


def init_models(config):
    models['user_login_model'] = {'email': fields.String(max_length=config["EMAIL_MAX_LENGTH"], required=True),
                                  'password': fields.String(max_length=config["PASSWORD_MAX_LENGTH"], required=True)}

    models['jwt_response_model'] = {'access_token': fields.String(required=True)}
    models['jwt_unauthorized_model'] = {"description": fields.String(),
                                        "error": fields.String(),
                                        "status_code": fields.Integer()}
    models['user_register_model'] = {'email': fields.String(max_length=config["EMAIL_MAX_LENGTH"], required=True),
                                     'name': fields.String(max_length=config["NAME_MAX_LENGTH"], required=True),
                                     'password': fields.String(max_length=config["PASSWORD_MAX_LENGTH"], required=True)}
    models['user_model'] = {'id': fields.String,
                            'email': fields.String(max_length=config["EMAIL_MAX_LENGTH"], required=True),
                            'name': fields.String(max_length=config["NAME_MAX_LENGTH"], required=True)}

    registration_error_keys = {}
    for key in models['user_register_model']:
        registration_error_keys[key] = fields.List(fields.String, attribute=key)

    models['registration_error_keys_model'] = registration_error_keys

    # dict(meta=fields.Nested(dict(code=fields.Integer)),
    #                                     response=fields.Nested(dict(errors=fields.Nested(registration_error_keys))))
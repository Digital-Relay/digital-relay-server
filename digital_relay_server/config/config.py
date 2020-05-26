import os

API_URL_PREFIX = '/api'
APP_URL = os.environ.get('APP_URL', 'http://localhost:4200')
# Generate a nice key using secrets.token_urlsafe()
SECRET_KEY = os.environ.get("SECRET_KEY", 'pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw')
# Bcrypt is set as default SECURITY_PASSWORD_HASH, which requires a salt
# Generate a good salt using: secrets.SystemRandom().getrandbits(128)
SECURITY_PASSWORD_SALT = os.environ.get("SECURITY_PASSWORD_SALT", '146585145368132386173505678016728509634')
SECURITY_SEND_REGISTER_EMAIL = True
SECURITY_REGISTERABLE = True
SECURITY_REGISTER_URL = API_URL_PREFIX + '/auth/register'
SECURITY_CONFIRMABLE = True
SECURITY_POST_CONFIRM_VIEW = APP_URL + '/login?emailConfirmed=1'
SECURITY_EMAIL_SUBJECT_CONFIRM = 'DXC RUN 4U - Potvrdenie e-mailovej adresy'
SECURITY_EMAIL_SUBJECT_REGISTER = 'DXC RUN 4U - Registrácia'

MAIL_SERVER = os.environ.get('MAIL_SERVER', 'localhost')
MAIL_PORT = int(os.environ.get('MAIL_PORT', 25))
MAIL_USERNAME = os.environ.get('MAIL_USERNAME', None)
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', None)
MAIL_DEFAULT_SENDER = ('DXC RUN 4U', 'info@dxcrun.eu')

WTF_CSRF_ENABLED = False

JWT_SECRET_KEY = 'pf9Wkove4IKEAXvy-cQkeDPhv9Cb3Ag-wyJILbq_dFw'
JWT_HEADER_TYPE = 'JWT'

SWAGGER_UI_DOC_EXPANSION = 'list'

MONGODB_DB = 'digital-relay'
MONGODB_HOST = os.environ.get('MONGODB_HOST', 'localhost')
MONGODB_PORT = int(os.environ.get('MONGODB_PORT', 27017))

EMAIL_MAX_LENGTH = 255
PASSWORD_MAX_LENGTH = 128
NAME_MAX_LENGTH = 255
TEAM_NAME_MAX_LENGTH = 255
TEAM_URL_MAX_LENGTH = 255

NUMBER_OF_STAGES = 20

INVITE_SUBJECT = 'DXC RUN 4U - Pozvánka do tímu'

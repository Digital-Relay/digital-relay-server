import secrets

API_URL_PREFIX = '/api'
# Generate a nice key using secrets.token_urlsafe()
SECRET_KEY = secrets.token_urlsafe()
# Bcrypt is set as default SECURITY_PASSWORD_HASH, which requires a salt
# Generate a good salt using: secrets.SystemRandom().getrandbits(128)
SECURITY_PASSWORD_SALT = secrets.SystemRandom().getrandbits(128).to_bytes(128, 'big')
WTF_CSRF_ENABLED = False
SECURITY_SEND_REGISTER_EMAIL = False
SECURITY_REGISTERABLE = True
SECURITY_REGISTER_URL = API_URL_PREFIX + '/auth/register'

JWT_AUTH_URL_RULE = API_URL_PREFIX + '/auth'
JWT_AUTH_USERNAME_KEY = 'email'

SWAGGER_UI_DOC_EXPANSION = 'list'

MONGODB_DB = 'digital-relay-users'
MONGODB_HOST = 'localhost'
MONGODB_PORT = 27017

EMAIL_MAX_LENGTH = 255
PASSWORD_MAX_LENGTH = 255
NAME_MAX_LENGTH = 255

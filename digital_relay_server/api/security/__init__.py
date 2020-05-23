from datetime import datetime

from flask_jwt_extended import decode_token
from flask_security import RegisterForm, ConfirmRegisterForm
from wtforms import StringField, IntegerField
from wtforms import validators

authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}


class ExtendedRegisterForm(RegisterForm):
    name = StringField('Displayed name', [validators.DataRequired()])
    tempo = IntegerField('Tempo', [validators.DataRequired(), validators.NumberRange(min=0)])


class ExtendedConfirmRegisterForm(ConfirmRegisterForm):
    name = StringField('Displayed name', [validators.DataRequired()])
    tempo = IntegerField('Tempo', [validators.DataRequired(), validators.NumberRange(min=0)])


def expiry_date_from_token(token):
    return datetime.utcfromtimestamp(decode_token(token)['exp'])

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

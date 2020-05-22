from flask_security import RegisterForm, ConfirmRegisterForm
from wtforms import StringField, FloatField
from wtforms.validators import DataRequired

authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    }
}


class ExtendedRegisterForm(RegisterForm):
    name = StringField('Displayed name', [DataRequired()])
    tempo = FloatField('Tempo', [DataRequired()])


class ExtendedConfirmRegisterForm(ConfirmRegisterForm):
    name = StringField('Displayed name', [DataRequired()])
    tempo = FloatField('Tempo', [DataRequired()])

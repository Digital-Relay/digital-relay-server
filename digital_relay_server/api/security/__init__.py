from flask_security import RegisterForm, ConfirmRegisterForm
from wtforms import StringField
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


class ExtendedConfirmRegisterForm(ConfirmRegisterForm):
    name = StringField('Displayed name', [DataRequired()])

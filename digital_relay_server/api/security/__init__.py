from flask_jwt_extended import decode_token
from flask_security import RegisterForm, ConfirmRegisterForm, ResetPasswordForm
from flask_security.forms import password_required, EqualTo
from wtforms import StringField, IntegerField, SubmitField, PasswordField
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


class ExtendedResetPasswordForm(ResetPasswordForm):
    submit = SubmitField('Obnoviť heslo')
    password = PasswordField('Nové heslo', validators=[password_required])
    password_confirm = PasswordField('Zopakujte heslo',
                                     validators=[
                                         EqualTo("password", message="Heslá sa nezhodujú"),
                                         password_required])


def expiry_date_from_token(token):
    return decode_token(token)['exp']

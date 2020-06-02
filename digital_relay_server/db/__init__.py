import math

from flask_mongoengine import MongoEngine
from flask_security import RoleMixin, UserMixin
from mongoengine import StringField, BooleanField, DateTimeField, ListField, ReferenceField, Document, IntField, \
    FloatField

from digital_relay_server.config.config import *

db = MongoEngine()


class Role(Document, RoleMixin):
    name = StringField(max_length=80, unique=True)
    description = StringField(max_length=255)


class User(Document, UserMixin):
    email = StringField(max_length=EMAIL_MAX_LENGTH, unique=True)
    password = StringField()
    active = BooleanField(default=False)
    confirmed_at = DateTimeField()
    roles = ListField(ReferenceField(Role), default=[])
    name = StringField(max_length=NAME_MAX_LENGTH)
    tempo = IntField(min_value=0)

    def get_security_payload(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'email': self.email,
            'tempo': self.tempo
        }


class Team(Document):
    name = StringField(max_length=TEAM_NAME_MAX_LENGTH, unique=True)
    donation = FloatField(min_value=0, default=0)
    start = IntField(min_value=0, max_value=DAY_SECONDS, default=DEFAULT_START)
    _members = ListField(StringField(max_length=EMAIL_MAX_LENGTH), db_field='members')
    _stages = ListField(StringField(), db_field='stages')

    @property
    def members(self):
        return self._members

    @members.setter
    def members(self, mems):
        for i, stage in enumerate(self.stages):
            if stage not in mems:
                self.stages[i] = mems[0]

        self._members = mems

    @property
    def stages(self):
        return self._stages

    @stages.setter
    def stages(self, participants):
        if len(participants) != len(self.stages):
            raise IndexError
        for p in participants:
            if p not in self.members:
                raise ValueError(p)

        self._stages = participants

    @property
    def url(self):
        return f'{APP_URL}/teams/{self.id}'

    @property
    def public_info(self):
        return dict(id=self.id, name=self.name, members=self.members, donation=self.donation, stages=[])

    def members_as_user_objects(self):
        emails = self.members
        users = list(User.objects(email__in=emails))
        for user in users:
            if user.email in emails:
                emails.remove(user.email)

        for email in emails:
            users.append(User(id=None, name=None, email=email))

        return users

    def set_default_stages(self):
        self._stages = (self.members * math.ceil(NUMBER_OF_STAGES / len(self.members)))[:NUMBER_OF_STAGES]

    def new_members(self, next_state_members):
        new_members = []
        for email in next_state_members:
            if email not in self.members:
                new_members.append(email)

        return new_members

import math

from flask_mongoengine import MongoEngine
from flask_security import RoleMixin, UserMixin
from mongoengine import StringField, BooleanField, DateTimeField, ListField, ReferenceField, Document, IntField

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
    members = ListField(StringField(max_length=EMAIL_MAX_LENGTH))
    stages = ListField(StringField())

    def check_stages_validity(self, participants):
        if len(participants) != len(self.stages):
            return False
        for p in participants:
            if p not in self.members:
                raise ValueError(p)
        return True

    def set_default_stages(self):
        self.stages = self.members * math.ceil(NUMBER_OF_STAGES / len(self.members))
        self.stages = self.stages[:NUMBER_OF_STAGES]

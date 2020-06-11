import math

from flask_mongoengine import MongoEngine
from flask_security import RoleMixin, UserMixin
from mongoengine import *

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
    push_subscriptions = ListField(DictField(), default=[])

    def get_security_payload(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'email': self.email,
            'tempo': self.tempo
        }


class Stage(Document):
    index = IntField(min_value=0, max_value=NUMBER_OF_STAGES - 1)
    email = StringField(max_length=EMAIL_MAX_LENGTH)
    estimated_time = IntField(min_value=0)
    real_time = IntField(min_value=0)
    length = IntField(min_value=0, default=STAGE_LENGTH)

    def load_values(self, stage_dict):
        self.index = stage_dict["index"]
        self.email = stage_dict["email"]
        try:
            self.estimated_time = stage_dict["estimated_time"]
        except KeyError:
            pass
        try:
            self.real_time = stage_dict["real_time"]
        except KeyError:
            pass
        try:
            self.length = stage_dict["length"]
        except KeyError:
            pass

    @staticmethod
    def from_dict(stage_dict):
        result = Stage()
        result.load_values(stage_dict=stage_dict)
        return result


class Team(Document):
    name = StringField(max_length=TEAM_NAME_MAX_LENGTH, unique=True)
    donation = FloatField(min_value=0, default=0)
    start = IntField(min_value=0, max_value=DAY_SECONDS, default=DEFAULT_START)
    _members = ListField(StringField(max_length=EMAIL_MAX_LENGTH), db_field='members')
    _stages = ListField(ReferenceField(Stage), db_field='stages')

    @property
    def members(self):
        return self._members

    @members.setter
    def members(self, mems):
        for i, stage in enumerate(self.stages):
            if stage.email not in mems:
                self.stages[i] = Stage(email=mems[0], index=i)

        self._members = mems

    @property
    def stages(self):
        return self._stages

    @stages.setter
    def stages(self, participants):
        if len(participants) != len(self.stages):
            raise IndexError
        parsed = []
        for p in participants:
            if isinstance(p, dict):
                p = Stage.from_dict(p)
            parsed.append(p)
        self.validate_participants(parsed)
        self._stages = parsed

    def validate_participants(self, stages):
        indexes = []
        for p in stages:
            if isinstance(p, dict):
                p = Stage.from_dict(p)
            if p.email not in self.members:
                raise ValueError(p)
            indexes.append(p.index)
        if len(indexes) != len(list(dict.fromkeys(indexes))):
            raise ValueError()

    @property
    def url(self):
        return f'{APP_URL}/teams/{self.id}'

    @property
    def registered_members(self):
        result = list(User.objects(email__in=self.members))
        return result

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
        stages = (self.registered_members * math.ceil(NUMBER_OF_STAGES / len(self.registered_members)))[
                 :NUMBER_OF_STAGES]
        result = []
        for i, user in enumerate(stages):
            estimated_time = user.tempo * STAGE_LENGTH
            result.append(Stage(email=user.email, index=i, estimated_time=estimated_time))

        self._stages = result

    def new_members(self, next_state_members):
        new_members = []
        for email in next_state_members:
            if email not in self.members:
                new_members.append(email)

        return new_members

    def save(self, force_insert=False, validate=True, clean=True, write_concern=None, cascade=None, cascade_kwargs=None,
             _refs=None, save_condition=None, signal_kwargs=None, **kwargs):
        [stage.save(force_insert=force_insert, validate=validate, clean=clean, write_concern=write_concern,
                    cascade=cascade, cascade_kwargs=cascade_kwargs, _refs=_refs, save_condition=save_condition,
                    signal_kwargs=signal_kwargs, **kwargs) for stage in self._stages]
        return super().save(force_insert, validate, clean, write_concern, cascade, cascade_kwargs, _refs,
                            save_condition, signal_kwargs, **kwargs)


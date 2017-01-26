# -*- coding: utf-8 -*-

import random
import hashlib
from string import letters
from google.appengine.ext import db

salt = "fart"

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    username = db.StringProperty(required = True)
    email = db.StringProperty()
    password_hw = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('username =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = cls.make_pw_hash(name, pw)
        return User(parent = users_key(),
                    username = name,
                    password_hw = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and cls.valid_pw(name, pw, u.password_hw):
            return u

    @classmethod
    def make_salt(cls,length = 5):
        return ''.join(random.choice(letters) for x in xrange(length))

    @classmethod    
    def make_pw_hash(cls,name, pw, salt = None):
        if not salt:
            salt = cls.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (salt, h)

    @classmethod    
    def valid_pw(cls,name, password, h):
        salt = h.split(',')[0]
        return h == cls.make_pw_hash(name, password, salt)
    
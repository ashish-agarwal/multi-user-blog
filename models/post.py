# -*- coding: utf-8 -*-

from google.appengine.ext import db
from user import User

class Post(db.Model):
    user = db.ReferenceProperty(User)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)
    
    @classmethod
    def query(cls, query_string, *args, **kwds):
        return db.GqlQuery(query_string, *args, **kwds)

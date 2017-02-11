# -*- coding: utf-8 -*-

from google.appengine.ext import db
from user import User

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    user = db.ReferenceProperty(User)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = blog_key())
    
    @classmethod
    def query(cls, query_string, *args, **kwds):
        return db.GqlQuery(query_string, *args, **kwds)

    def getUserName(self):
        """
            Gets username of the person, who wrote the blog post.
        """
        user = User.by_id(self.user)
        return user.name
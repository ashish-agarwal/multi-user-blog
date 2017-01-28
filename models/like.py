# -*- coding: utf-8 -*-

from google.appengine.ext import db
from user import User
from post import Post

class Like(db.Model):
    user = db.ReferenceProperty(User)
    post = db.ReferenceProperty(Post)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def find(cls, uid, pid,, *args, **kwds):
        return db.GqlQuery("SELECT * FROM Like where user = "+uid+" AND post="+pid)
    
    @classmethod
    def query(cls, query_string, *args, **kwds):
        return db.GqlQuery(query_string, *args, **kwds)

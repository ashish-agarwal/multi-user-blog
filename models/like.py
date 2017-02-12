# -*- coding: utf-8 -*-

from google.appengine.ext import db
from user import User
from post import Post


class Like(db.Model):
    user = db.ReferenceProperty(User)
    post = db.ReferenceProperty(Post)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    liked = db.BooleanProperty()

    @classmethod
    def find(cls, uid, pid, *args, **kwds):
        # return db.GqlQuery("SELECT * FROM Like where user = "+uid+" AND
        # post="+pid)
        u = Like.all().filter('user =', uid).filter('post = ', pid).get()
        return u

    @classmethod
    def query(cls, query_string, *args, **kwds):
        return db.GqlQuery(query_string, *args, **kwds)

    @classmethod
    def by_user(self, user):
        """
            This method fetches List of like objects from database,
            whose id is {user}.
        """
        u = Like.all().filter('user =', user).get()
        return u

    @classmethod
    def by_post(self, user):
        """
            This method fetches List of like objects from database,
            whose post is {post}.
        """
        # return db.GqlQuery("SELECT * FROM Like where  post="+user).count()
        u = Like.all().filter('post =', user).count()
        return u

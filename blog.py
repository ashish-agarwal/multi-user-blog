# -*- coding: utf-8 -*-

import os
import webapp2
import jinja2
import hmac
import re

# Importing db models
from models.user import User
from models.post import Post
from models.like import Like
from models.comment import Comment
from google.appengine.ext import db

import logging

logger = logging.getLogger()

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
secret = "ds"


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


def like_key(name='default'):
    return db.Key.from_path('like', name)


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):

    def get(self):
        posts = Post.all()
        likes = Like.all().filter('user =', self.user)

        for post in posts:
            post.liked = any(like.post.key().id() == post.key().id()
                             for like in likes)
            print post

        self.render('front-page.html', posts=posts, user=self.user,
                    likes=likes, error=self.request.get('error'))


class Login(BlogHandler):

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('signup-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect("/?error=logged%20out%20of%20application%20successfully")


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("new-post.html")
        else:
            self.redirect("/?error=please%20login%20to%20the%20application")

    def post(self):
        if not self.user:
            self.redirect("/?error=please%20login%20to%20the%20application")

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), user=self.user,
                     subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("new-post.html", subject=subject,
                        content=content, error=error)


class PostHandler(BlogHandler):

    def get(self, id):
        key = db.Key.from_path('Post', int(id), parent=blog_key())
        post = db.get(key)
        likes = Like.by_post(post)
        comments = db.GqlQuery("select * from Comment where post = " +
                               id + "order by created desc")
        logger.info(comments)
        logger.info(comments.count())
        self.render("post-details.html", p=post, l=likes,
                    comments=comments, error=self.request.get("error"))

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        """
            On posting comment, new comment tuple is created and stored,
            with relationship data of user and post.
        """
        c = ""
        if(self.user):
            # On commenting, it creates new comment tuple
            if(self.request.get('comment')):
                c = Comment(parent=blog_key(), user=self.user,
                            post=int(post_id),
                            comment=self.request.get('comment'))
                c.put()
        else:
            self.redirect("/login?error=You need to login before " +
                          "performing edit, like or commenting.!!")
            return

        comments = db.GqlQuery("select * from Comment where post = " +
                               post_id + "order by created desc")

        likes = db.GqlQuery("select * from Like where post=" + post_id)

        self.redirect('/blog/' + post_id)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Register(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        u = User.by_name(self.username)

        if u:
            params['error_username'] = 'That user already exists.'
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class LikeHandler(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self, id):
        if self.user is None:
            self.redirect("/?error=please%20login%20to%20the%20application")
            return

        self.liked = bool(self.request.get('liked'))
        post = Post.by_id(int(id))
        l = Like.find(self.user, post)

        if l:
            self.redirect("/blog/" + id +
                          "?error=You already liked this " +
                          "post.!!")
            return

        if self.user.key().id() == post.user.key().id():
            self.redirect("/blog/" + id +
                          "?error=You cannot like your " +
                          "post.!!")
            return
        l = Like(parent=like_key(), user=self.user,
                 post=post, liked=self.liked)
        l.put()
        self.redirect('/')


class EditHandler(BlogHandler):

    def get(self, id):
        post = Post.by_id(int(id))
        error = self.request.get("error")
        self.render("new-post.html", subject=post.subject,
                    content=post.content, error=error)

    def post(self, id):
        if not self.user:
            return self.redirect("/?error=please%20login%20to%20the%20application")

        subject = self.request.get('subject')
        content = self.request.get('content')

        p = Post.by_id(int(id))
        if self.user.key().id() != p.user.key().id():
            self.redirect(
                "/?error=You%20dont%20have%20permissions%20to%20edit%20this%20post")
            return

        if subject and content:
            p.subject = subject
            p.content = content
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("new-post.html", subject=subject,
                        content=content, error=error)


class DeleteHandler(BlogHandler):

    def get(self, id):
        if not self.user:
            return self.redirect("/?error=please%20login%20to%20the%20application")

        # p = Post.by_id(int(id))
        l = Like.all().filter('post =', id).get()
        print l
        if l.count() > 0:
            for like in l:
                print like
                like.delete()
        self.redirect('/')


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user.key().id() == self.user.key().id():
                c.delete()
                self.redirect("/blog/" + post_id)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this comment.")
        else:
            self.redirect("/?error=You need to be logged, in order to " +
                          "delete your comment!!")


class EditComment(BlogHandler):

    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user.key().id() == self.user.key().id():
                self.render("editcomment.html", comment=c.comment)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=You don't have access to edit this " +
                              "comment.")
        else:
            self.redirect("/?error=You need to be logged, in order to" +
                          " edit your post!!")

    def post(self, post_id, comment_id):
        """
            Updates post.
        """
        if not self.user:
            self.redirect('/blog')

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comment',
                                   int(comment_id), parent=blog_key())
            c = db.get(key)
            c.comment = comment
            c.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("post-details.html", subject=subject,
                        content=content, error=error)


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/blog/(\d+)', PostHandler),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ('/blog/edit/(\d+)', EditHandler),
                               ('/blog/delete/(\d+)', DeleteHandler),
                               ('/blog/(\d+)/like', LikeHandler)
                               ],
                              debug=True)

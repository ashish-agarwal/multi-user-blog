# -*- coding: utf-8 -*-

import os
import webapp2
import jinja2
import hmac
# Importing db models
from models.user import User
from models.post import Post
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
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


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)


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

    def login(self,user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')        

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
    
class MainPage(BlogHandler):
  def get(self):
    posts = db.GqlQuery('select * from Post')
    print "posts",posts
    # self.write(posts)      
    self.render('front-page.html',posts = posts)

class Register(BlogHandler):
  def get(self):
    f = User.register("ads","ADS","")
    f.put()
    self.login(f)     
    self.write("hello")

  def post(self):
    u = User.register(self.request.get('username'), self.request.get('password'), self.request.get('email'))
    u.put()
    self.login(u)     
    self.write("signed up successfully and also cookie is set")
    
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
            self.render('signup-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("new-post.html")
        else:
            self.redirect("/")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), user = self.user, subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class PostHandler(BlogHandler):
    def get(self, id):
        key = db.Key.from_path('Post', int(id), parent=blog_key())
        print id,key
        # post = Post.by_id(key)
        post = db.get(key)
        print post
        self.render("post.html",p = post)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/register',Register),
                               ('/login',Login),
                               ('/logout',Logout),
                               ('/newpost', NewPost),
                               ('/blog/(\d+)',PostHandler)
                               ],
                              debug=True)
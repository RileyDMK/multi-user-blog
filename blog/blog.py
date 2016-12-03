import os
import re
import jinja2
import webapp2
import hashlib
import hmac
import string
import random

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)
secret = 'asdlfaje09349q8[3fe38y33ru37y7;fu'

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt():
    return ''.join(random.choice(string.letters)for i in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, pw, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, pw, salt)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie','%s=%s; Path=/'%(name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    #checks that user is logged in
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    #New columns. Changes required.
    user_id = db.StringProperty(required = True)
    likes = db.IntegerProperty(default=0)
    likers = db.StringListProperty()
    dislikes = db.IntegerProperty(default = 0)

class Comment(db.Model):
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    user_id = db.IntegerProperty(required = True)
    blog = db.ReferenceProperty(Blog, collection_name='blog_comments')

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    #classmethod means it acts on the class itself, not an instance
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)
        #was User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        #was User.all()....
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(name = name, pw_hash = pw_hash, email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Signup(Handler):

    def get(self):
        author = self.read_secure_cookie('user_id')
        if author:
            self.render("signup.html", author=author)
        else:
            self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

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

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            #set cookie
            self.login(u)
            self.redirect('/welcome')

class Login(Handler):
    def get(self):
        author = self.read_secure_cookie('user_id')
        if author:
            self.render('login.html', author=author)
        else:
            self.render('login.html')
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid Login'
            self.render('login.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')

class HomePage(Handler):
    def get(self):
        author = self.read_secure_cookie('user_id')
        msg = self.request.get('msg')
        if author:
            self.render("base.html", author = author, msg = msg)
        else:
            self.render("base.html")

class Welcome(Handler):
    def get(self):
        if self.user:
            user_id = self.read_secure_cookie('user_id')
            self.render('welcome.html', username = self.user.name, user_id = user_id)
        else:
            self.redirect('/signup')

#Shows ten newest blogs
class MainBlogPage(Handler):
    def get(self):
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC LIMIT 10")
        user_id = self.read_secure_cookie('user_id')
        self.render("blog.html", blogs = blogs, user_id = user_id)

#Goes to a page with the new blog displayed
class BlogPage(Handler):
    def get(self, blog_id):
        #key = db.Key.from_path('Blog', int(blog_id))
        #blog = db.get(key)
        blog = Blog.get_by_id(int(blog_id))

        if not blog:
            self.error(404)
            return
        #comments = db.GqlQuery("SELECT * FROM Comment ORDER BY created DESC ")
        #comments = []
        #for comment in blog.blog_comments:
            #comments.append(comment.content)


        author = self.read_secure_cookie('user_id')
        if author:
            self.render("permalink.html", blog=blog, author = author)
        else:
            self.render("permalink.html", blog=blog)

    def post(self, blog_id):
        user_id = self.read_secure_cookie('user_id')
        if self.request.get('delete'):
            blog = Blog.get_by_id(int(blog_id))
            if blog.user_id == user_id:
                blog.delete()
                msg = "Blog Deleted"
                self.redirect('/?msg=%s'%msg)
            else:
                self.redirect('/login')
        elif self.request.get('edit'):
            blog = Blog.get_by_id(int(blog_id))
            user_id = self.read_secure_cookie('user_id')
            self.redirect('/blog/edit/%s' % blog_id)
        elif self.request.get('like'):
            blog = Blog.get_by_id(int(blog_id))
            if not user_id in blog.likers:
                blog.likes += 1
                blog.likers.append(user_id)
                blog.put()
                self.redirect('/blog')
            else:
                self.redirect('/blog')
        elif self.request.get('dislike'):
            blog = Blog.get_by_id(int(blog_id))
            if not user_id in blog.likers:
                blog.dislikes += 1
                blog.likers.append(user_id)
                blog.put()
                self.redirect('/blog')
            else:
                self.redirect('/blog')
        elif self.request.get('view'):
            self.redirect('/blog/%s'%blog_id)
        # elif self.request.get('post-comment'):
        #     content=""
        #     if self.request.get('comment_text'):
        #         content = self.request.get('comment_text')
        #     c = Comment(content=content, user_id=int(user_id), blog_id=int(blog_id))
        #     c.put()
        #     self.redirect('/blog/%s'%blog_id)
        elif self.request.get('comment'):
             #blog = Blog.get_by_id(int(blog_id))
             #user_id = self.read_secure_cookie('user_id')
             self.redirect('/comment/%s'%blog_id)
        elif self.request.get('delete-coment'):
            comment = self.request.get('c')
            if c.user_id == user_id:
                comment.delete()
                self.redirect('/blog/%s'%blog_id)
            else:
                self.redirect('/blog/%s'%blog_id)
        elif self.request.get('edit-comment'):
            content = self.request.get("content")
            self.render("comment.html", content = content)



class CommentHandler(Handler):
    def render_newcomment(self, content="", error=""):
        author = self.read_secure_cookie('user_id')
        if author:
            self.render("comment.html", content=content, error=error, author=author)
        else:
            self.render("comment.html", content=content, error=error)

    def get(self, blog_id):
        self.render_newcomment()

    def post(self, blog_id):
        content = self.request.get("content")
        user_id = self.read_secure_cookie('user_id')
        blog = Blog.get_by_id(int(blog_id))

        if content:
            c = Comment(content = content, user_id = int(user_id), blog=blog)
            c.put()
            link_id = blog.key().id()
            self.redirect('/blog/%s' % link_id)
        else:
            error = "Content is required!"
            self.render_newcomment(content=content, error=error)


class EditPost(Handler):
    def get(self, blog_id, subject="", content="", error=""):
        author = self.read_secure_cookie('user_id')
        b = Blog.get_by_id(int(blog_id))
        subject = b.subject
        content = b.content
        if author:
            self.render("edit.html", blog_id=blog_id, subject=subject, content=content, error=error, author = author)
        else:
            self.render("edit.html", blog_id=blog_id, subject=subject, content=content, error=error)

    def post(self, blog_id):
        b = Blog.get_by_id(int(blog_id))
        subject = self.request.get("subject")
        content = self.request.get("content")
        user_id = b.user_id
        if self.request.get('submit'):
            if user_id == self.read_secure_cookie('user_id'):
                if subject and content:
                    b.subject = subject
                    b.content = content
                    b.put()
                    self.redirect('/blog/%s' % blog_id)

                else:
                    error = "Both subject and content are required!"
                    self.render("edit.html", blog_id=blog_id, subject=subject, content=content, error=error)
            else:
                error = "You do not own this blog!"
                self.render("edit.html", blog_id=blog_id, subject=subject, content=content, error=error)
        elif self.request.get('cancel'):
            self.redirect('/blog/%s' % b.key().id())


class NewPost(Handler):
    def render_newpost(self, subject="", content="", error=""):
        author = self.read_secure_cookie('user_id')
        if author:
            self.render("newpost.html", subject=subject, content=content, error=error, author=author)
        else:
            self.render("newpost.html", subject=subject, content=content, error=error)

    def get(self):
        self.render_newpost()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        user_id = self.read_secure_cookie('user_id')

        if subject and content:
            b = Blog(subject = subject, content = content, user_id = user_id)
            b.put()
            link_id = b.key().id()
            self.redirect('/blog/%s' % str(link_id))
        else:
            error = "Both subject and content are required!"
            self.render_newpost(subject=subject, content=content, error=error)

app = webapp2.WSGIApplication([('/', HomePage),
                               ('/signup', Register),
                               ('/logout', Logout),
                               ('/login', Login),
                               ('/welcome', Welcome),
                               ('/blog', MainBlogPage),
                               ('/comment/([0-9]+)', CommentHandler),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/([0-9]+)',BlogPage)], debug = True)

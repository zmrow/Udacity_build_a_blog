import os
import re
import random
import hashlib
import hmac
from string import letters
import jinja2
import webapp2

from google.appengine.ext import db

# Jinja env setup taken from Googles sample app here:
# https://github.com/GoogleCloudPlatform/appengine-guestbook-python/blob/master/guestbook.py
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
JINJA_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

SECRET = '$w0rdf1sh'
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def valid_username(username):
    return username and USER_RE.match(username)

def valid_password(password):
    return password and PASS_RE.match(password)

def valid_email(email):
    return not email or EMAIL_RE.match(email)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def exists(cls, name):
        user = User.all().filter('name =', name).get()
        return user

    @classmethod
    def create(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(name=name, pw_hash=pw_hash, email=email)


class BlogPost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.ReferenceProperty(User, required=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = JINJA_ENV.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
                'Set-Cookie',
                '%s=%s, Path=/' % (name, cookie_val)
                )

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def logged_in(self):
        cookie_val = self.request.cookies.get('user_id')
        return cookie_val and check_secure_val(cookie_val)


class Blog(Handler):
    def get(self):
        posts = db.GqlQuery('select * from BlogPost order by created DESC')
        self.render('index.html', posts=posts)


class MyBlog(Handler):
    def get(self):
        cookie_val = self.request.cookies.get('user_id')
        uid = cookie_val and check_secure_val(cookie_val)
        user = uid and User.get_by_id(int(uid))
        posts = [post for post in BlogPost.all().filter('created_by =', user)]
        self.render('myblog.html', posts=posts, user=user)


class Entry(Handler):
    def get(self, post_id):
        # self.content.replace('\n', '<br>')
        post = BlogPost.get_by_id(int(post_id))
        self.render('permalink.html', post=post)


class EditPost(Handler):
    def get(self, post_id):
        edit_error = 'Only logged in users can edit posts'

        cookie_val = self.request.cookies.get('user_id')
        uid = cookie_val and check_secure_val(cookie_val)

        if uid:
            post = BlogPost.get_by_id(int((post_id)))
            self.render('edit_post.html', subject=post.subject, content=post.content)
        else:
            error = edit_error
            self.redirect('blog')

    def post(self, post_id):
        edit_error = 'Please enter both a subject and content'
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = BlogPost.get_by_id(int(post_id))
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('blog/%s' % str(post.key().id()))
        else:
            self.render('edit_post.html', error=edit_error)


class NewPost(Handler):
    def get(self, subject='', content='', error=''):
        self.render("newpost.html")

    def post(self):
        cookie_val = self.request.cookies.get('user_id')
        uid = cookie_val and check_secure_val(cookie_val)
        user = uid and User.get_by_id(int(uid))
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = BlogPost(subject=subject, content=content, created_by=user)
            post.put()
            post_id = post.key().id()

            self.redirect('%s' % post_id)
        else:
            error = "Please enter both a subject and blog post"
            self.render("newpost.html", subject=subject, content=content, error=error)


class Signup(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        has_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username, email = email)

        if not valid_username(username):
            params['user_error'] = 'That\'s not a valid username'
            has_error = True

        if not valid_password(password):
            params['password_error'] = 'That\'s not a valid password'
            has_error = True
        elif password != verify:
            params['verify_error'] = 'Your passwords don\'t match'
            has_error = True

        if not valid_email(email):
            params['email_error'] = 'That\'s not a valid email'
            has_error = True

        if has_error:
            self.render('signup.html', **params)
        else:
            # Make sure the user doesn't already exist
            if User.exists(username):
                params['user_error'] = 'That user already exists'
                self.render('signup.html', **params)
            else:
                user = User.create(name=username, pw=password, email=email)
                user.put()
                self.set_secure_cookie('user_id', str(user.key().id()))
                #self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/' % str(username))
                self.redirect('welcome')


class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        login_error = 'Invalid login'
        username = self.request.get('username')
        password = self.request.get('password')

        # Check if user exists
        user = User.exists(str(username))
        if user and valid_pw(username, password, str(user.pw_hash)):
            self.set_secure_cookie('user_id', str(user.key().id()))
            self.redirect('welcome')
        else:
            self.render('login.html', login_error=login_error)


class Logout(Handler):
    def get(self):
        self.response.headers.add_header(
                'Set-Cookie',
                'user_id=; Path=/')
        self.redirect('/')

class Welcome(Handler):
    def get(self):
        cookie_val = self.request.cookies.get('user_id')
        uid = cookie_val and check_secure_val(cookie_val)
        user = uid and User.get_by_id(int(uid))
        if user:
            self.render('welcome.html', user=user, username=user.name)
        else:
            self.redirect('signup')


app = webapp2.WSGIApplication([('/', Blog),
                               ('/blog', Blog),
                               ('/blog/my', MyBlog),
                               (r'/blog/(\d+)', Entry),
                               (r'/blog/(\d+)/edit', EditPost),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Signup),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/welcome', Welcome)],
                               debug=True)

import os
import re
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

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class BlogPost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = JINJA_ENV.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class Blog(Handler):
    def get(self):
        posts = db.GqlQuery('select * from BlogPost order by created DESC')
        self.render('index.html', posts=posts)


class Entry(Handler):
    def get(self, post_id):
        # self.content.replace('\n', '<br>')
        post = BlogPost.get_by_id(int(post_id))
        self.render('permalink.html', post=post)


class NewPost(Handler):
    def get(self, subject='', content='', error=''):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = BlogPost(subject=subject, content=content)
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
            self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/' % str(username))
            self.redirect('welcome')


class Welcome(Handler):
    def get(self):
        username = self.request.cookies.get('name')
        self.render('welcome.html', username=username)

app = webapp2.WSGIApplication([('/blog', Blog),
                               (r'/blog/(\d+)', Entry),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Signup),
                               ('/blog/welcome', Welcome)],
                               debug=True)

import os
import re
import jinja2
import webapp2
import codecs

# Jinja env setup taken from Googles sample app here:
# https://github.com/GoogleCloudPlatform/appengine-guestbook-python/blob/master/guestbook.py
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
JINJA_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = JINJA_ENV.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class Blog(Handler):
    def get(self, text=''):
        self.render("index.html", posts=posts)

    def post(self):
        text = self.request.get('text')
        rot13_text = codecs.encode(text, 'rot_13')
        self.render("rot13.html", text = rot13_text)


class Entry(Handler):
    def get(self, username='',
            email='',
            user_error='',
            password_error='',
            verify_error='',
            email_error=''):
        self.render("user_signup.html", username=username, email=email)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')


class NewPost(Handler):
    def get(self):
        username = self.request.get('username')
        self.render("welcome.html", username=username)

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

app = webapp2.WSGIApplication([('/blog', Blog),
                               (r'/blog/(\d+)', Entry),
                               ('/blog/newpost', NewPost)],
                               debug=True)

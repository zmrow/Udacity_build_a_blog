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

def valid_username(username):
    if username:
        user_regx = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return user_regx.match(username)

def valid_password(password):
    if password:
        passwd_regx = re.compile(r"^.{3,20}$")
        return passwd_regx.match(password)

def valid_email(email):
    if email:
        email_regx = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return email_regx.match(email)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = JINJA_ENV.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class UserSignup(Handler):
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
        print email

        valid_user = valid_username(username)
        valid_pass = valid_password(password)
        valid_verify = valid_password(verify)
        valid_emaill = valid_email(email)

        uer = 'That\'s not a valid username.'
        per = 'That\'s not a valid password.'
        ver = 'Your passwords didn\'t match.'
        eer = 'That\'s not a valid email'

        u = ''
        p = ''
        v = ''
        e = ''

        # The following is an EXTREMELY BAD ALGORITHM but I need to get this done.
        if (valid_user and valid_pass and valid_verify and valid_emaill):
            if password == verify:
                self.redirect("/welcome?username=%s" % username)
            else:
                v = ver
                self.render("user_signup.html",
                        username=username,
                        email=email,
                        verify_error=v)

        if not valid_user:
            u = uer

        if not valid_pass:
            p = per

        if (valid_pass and valid_verify) and not (password == verify):
            v = ver

        if email and not valid_emaill:
            e = eer

        self.render("user_signup.html",
                username=username,
                email=email,
                user_error=u,
                password_error=p,
                verify_error=v,
                email_error=e)


class WelcomePage(Handler):
    def get(self):
        username = self.request.get('username')
        self.render("welcome.html", username=username)


class MainPage(Handler):
    def get(self, text=''):
        self.render("rot13.html", text=text)

    def post(self):
        text = self.request.get('text')
        rot13_text = codecs.encode(text, 'rot_13')
        self.render("rot13.html", text = rot13_text)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/user_signup', UserSignup),
                               ('/welcome', WelcomePage)],
                               debug=True)

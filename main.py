import os
import re
import random
import hashlib
import hmac
import time
from string import letters
from utils import login_required
import jinja2
import webapp2

from google.appengine.ext import db


def make_secure_val(val):
    SECRET = '$w0rdf1sh'
    return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)


class User(db.Model):
    """User db Model"""
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def exists(cls, name):
        """Class method to determine if a user exists"""
        user = User.all().filter('name =', name).get()
        return user

    @classmethod
    def create(cls, name, pw, email=None):
        """Class method to create a User object"""
        pw_hash = make_pw_hash(name, pw)
        return User(name=name, pw_hash=pw_hash, email=email)


class BlogPost(db.Model):
    """Blog Post db Model"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.ReferenceProperty(User, required=True)
    likes = db.StringListProperty()

    @classmethod
    def exists(cls, post_id):
        """Class method to determine if a blog post exists"""
        post = BlogPost.get_by_id(int(post_id))
        return post


class Comment(db.Model):
    """Comment db Model"""
    author = db.ReferenceProperty(User, required=True)
    content = db.TextProperty(required=True)
    post_id = db.ReferenceProperty(BlogPost, required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def exists(cls, comment_id):
        """Class method to determine if a comment exists"""
        comment = Comment.get_by_id(int(comment_id))
        return comment


class Handler(webapp2.RequestHandler):
    """Main Handler class for commonly used methods"""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        # Jinja env setup taken from Googles sample app here:
        # https://github.com/GoogleCloudPlatform/appengine-guestbook-python/
        # blob/master/guestbook.py
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            extensions=['jinja2.ext.autoescape'],
            autoescape=True)

        params['user'] = self.user
        t = jinja_env.get_template(template)
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

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))


class RootPage(Handler):
    """Handler for main page"""
    def get(self):
        self.redirect('blog')


class Blog(Handler):
    """Additional Handler for main page"""
    def get(self):
        posts = db.GqlQuery('select * from BlogPost order by created DESC')
        self.render('index.html', posts=posts)


class MyBlog(Handler):
    """Handler for page container only currently logged in users posts"""
    @login_required
    def get(self):
        posts = []
        for post in BlogPost.all().filter('created_by =', self.user):
            posts.append(post)

        self.render('myblog.html', posts=posts)


class Entry(Handler):
    """Handler for viewing a single entry"""
    def get(self, post_id):
        if not BlogPost.exists(post_id):
            self.error(404)
            return

        post = BlogPost.get_by_id(int(post_id))
        comments = [c for c in Comment.all().filter('post_id =', post)]
        self.render('permalink.html', post=post, comments=comments)


class EditPost(Handler):
    """Handler for editing a single entry"""
    @login_required
    def get(self, post_id):
        if not BlogPost.exists(post_id):
            self.error(404)
            return

        post = BlogPost.get_by_id(int(post_id))

        if self.user and self.user.key() == post.created_by.key():
            self.render('edit_post.html', post=post)
        # If the current user is not = the posts' author, throw an error
        elif self.user.key() != post.created_by.key():
            error = 'You can\'t edit posts you did not create!'
            self.render('permalink.html', post=post, error=error)
        else:
            # We should never get here as there will be no user, handle anyway
            error = 'You are not logged in; you cannot edit posts!'
            self.render('permalink.html', post=post, error=error)

    @login_required
    def post(self, post_id):
        edit_error = 'Please enter both a subject and content'
        user_error = 'You can\'t edit posts you did not create!'
        subject = self.request.get('subject')
        content = self.request.get('content')
        post = BlogPost.get_by_id(int(post_id))

        if self.user.key() == post.created_by.key():
            if subject and content:
                post = BlogPost.get_by_id(int(post_id))
                post.subject = subject
                post.content = content
                post.put()
                return self.redirect('/blog/%s' % str(post.key().id()))
            else:
                self.render('edit_post.html', post=post, error=edit_error)
        else:
            self.render('edit_post.html', post=post, error=user_error)


class DeletePost(Handler):
    """Handler for deleting a single entry"""
    @login_required
    def get(self, post_id):
        if not BlogPost.exists(post_id):
            self.error(404)
            return

        post = BlogPost.get_by_id(int((post_id)))

        if self.user.key() == post.created_by.key():
            self.render('delete_post.html', post=post)
        # If the current user is not = the posts' author, throw an error
        elif self.user.key() != post.created_by.key():
            error = 'You can\'t delete posts you did not create!'
            self.render('permalink.html', post=post, error=error)
        else:
            # We should never get here as there will be no user, handle anyway
            error = 'You are not logged in; you cannot delete posts!'
            self.render('permalink.html', post=post, error=error)

    @login_required
    def post(self, post_id):
        alert = 'Blog post successfully deleted'
        error = 'You can\'t delete posts you did not create!'
        post = BlogPost.get_by_id(int(post_id))

        if self.user.key() == post.created_by.key():
            post.delete()
            self.render('welcome.html', alert=alert)
        else:
            self.render('permalink.html', post=post, error=error)


class LikePost(Handler):
    """Handler for liking a single entry"""
    @login_required
    def post(self, post_id):
        post = BlogPost.get_by_id(int(post_id))

        if self.user.key() != post.created_by.key():
            if self.user.name not in post.likes:
                post.likes.append(self.user.name)
                post.put()
                time.sleep(.5)
                self.redirect('/')
            else:
                error = 'You may only like a post one time'
                self.render('permalink.html', post=post, error=error)
        else:
            error = 'You may not like your own posts'
            self.render('permalink.html', post=post, error=error)


class NewPost(Handler):
    """Handler for creating a single entry"""
    @login_required
    def get(self, subject='', content='', error=''):
        self.render("newpost.html")

    @login_required
    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = BlogPost(subject=subject,
                            content=content,
                            created_by=self.user,
                            likes=[]
                            )
            post.put()
            post_id = post.key().id()

            self.redirect('%s' % post_id)
        else:
            error = "Please enter both a subject and blog post"
            self.render("newpost.html",
                        subject=subject,
                        content=content,
                        error=error
                        )


class NewComment(Handler):
    """Handler for creating a single comment"""
    def get(self, post_id, error=''):
        if not self.user:
            self.redirect('%s' % post_id)

        if not BlogPost.exists(post_id):
            self.error(404)
            return

        self.render("post_comment.html", post_id=post_id)

    def post(self, post_id):
        if not self.user:
            self.redirect('/')

        post = BlogPost.get_by_id(int(post_id))
        content = self.request.get('content')

        if content:
            comment = Comment(author=self.user, content=content, post_id=post)
            comment.put()
            time.sleep(.5)  # Give the db time to operate before redirecting

            self.redirect('/blog/%s' % post_id)
        else:
            error = "Please enter your comments!"
            self.render("post_comment.html", content=content, error=error)


class EditComment(Handler):
    """Handler for editing a single comment"""
    def get(self, post_id, comment_id):
        if not BlogPost.exists(post_id) or not Comment.exists(comment_id):
            self.error(404)
            return

        post = BlogPost.get_by_id(int((post_id)))
        comment = Comment.get_by_id(int(comment_id))

        if self.user and self.user.key() == comment.author.key():
            self.render('edit_comment.html', post=post, comment=comment)
        # If the current user is not = comments' author, throw an error
        elif self.user.key() != comment.author.key():
            error = 'You can\'t edit comments you did not create!'
            self.render('permalink.html',
                        post=post,
                        comment=comment,
                        error=error
                        )
        else:
            # We should never get here as there will be no user, handle anyway
            error = 'You are not logged in; you cannot edit posts!'
            self.render('permalink.html',
                        post=post,
                        comment=comment,
                        error=error
                        )

    def post(self, post_id, comment_id):
        edit_error = 'Please enter your comments!'
        content = self.request.get('content')

        if content:
            post = BlogPost.get_by_id(int((post_id)))
            comment = Comment.get_by_id(int(comment_id))
            comment.content = content
            comment.put()
            time.sleep(.5)
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            self.render('edit_comment.html', error=edit_error)


class DeleteComment(Handler):
    """Handler for deleting a single comment"""
    def get(self, post_id, comment_id):
        if not BlogPost.exists(post_id) or not Comment.exists(comment_id):
            self.error(404)
            return

        post = BlogPost.get_by_id(int((post_id)))
        comment = Comment.get_by_id(int(comment_id))

        if self.user and self.user.key() == comment.author.key():
            self.render('delete_comment.html', post=post, comment=comment)
        # If the current user is not = the comments' author, throw an error
        elif self.user.key() != comment.created_by.key():
            error = 'You can\'t delete comments you did not create!'
            self.render('permalink.html',
                        post=post,
                        comment=comment,
                        error=error
                        )
        else:
            # We should never get here as there will be no user, handle anyway
            error = 'You are not logged in; you cannot delete comments!'
            self.render('permalink.html',
                        post=post,
                        comment=comment,
                        error=error
                        )

    def post(self, post_id, comment_id):
        alert = 'Comment successfully deleted'
        comment = Comment.get_by_id(int(comment_id))

        comment.delete()

        self.render('welcome.html', alert=alert)


class Signup(Handler):
    """Handler for signing up"""
    def get(self):
        if self.user:
            self.redirect('welcome')

        self.render('signup.html')

    def post(self):
        has_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username, email=email)

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
                self.redirect('welcome')


class Login(Handler):
    """Handler for logging in"""
    def get(self):
        if self.user:
            self.redirect('welcome')
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
    """Handler for logging out"""
    def get(self):
        self.response.headers.add_header(
                'Set-Cookie',
                'user_id=; Path=/')
        self.redirect('/')


class Welcome(Handler):
    """Handler for user home/welcome page"""
    def get(self, alert=''):
        if self.user:
            self.render('welcome.html', alert=alert)
        else:
            self.redirect('signup')


# Main router
app = webapp2.WSGIApplication([
    ('/', RootPage),
    ('/blog', Blog),
    ('/blog/my', MyBlog),
    (r'/blog/(\d+)', Entry),
    (r'/blog/(\d+)/edit', EditPost),
    (r'/blog/(\d+)/delete', DeletePost),
    (r'/blog/(\d+)/like', LikePost),
    ('/blog/newpost', NewPost),
    (r'/blog/(\d+)/comment', NewComment),
    (r'/blog/(\d+)/comment/(\d+)/edit', EditComment),
    (r'/blog/(\d+)/comment/(\d+)/delete', DeleteComment),
    ('/blog/signup', Signup),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/welcome', Welcome)],
    debug=True)

import os
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

app = webapp2.WSGIApplication([('/blog', Blog),
                               (r'/blog/(\d+)', Entry),
                               ('/blog/newpost', NewPost)],
                               debug=True)

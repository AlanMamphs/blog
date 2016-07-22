import webapp2
import jinja2
import os
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)



class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)


def blog_key(name='default'):
	return db.Key.from_path('blog', name)

class Blog(db.Model, Handler):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	lastmodified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_txt = self.content.replace('\n', '<br>')
		self.render_str("post.html", b = self)

class BlogFront(Handler):
	def get(self):
		blog = db.GqlQuery('SELECT * FROM Blog ORDER BY created DESC LIMIT 10')
		self.render('blog.html', blog=blog)

class PostPage(Handler):
	def get(self, post_id):
		key = db.Key.from_path('Blog', int(post_id), parent = blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			self.write('Error 404. No post found')
			return

		self.render('permalink.html', post=post)
class NewPost(Handler):
	def np_render(self, subject='', content = '', error=''):
		self.render('newpost.html', subject=subject, content=content, error=error)
	def get(self):
		self.render('newpost.html')
	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			b = Blog(parent=blog_key(), subject=subject, content=content)
			b.put()
			self.redirect('/blog/%s'% str(b.key().id()))
		else:
			error = "Subject or Blog is missing."
			self.np_render(subject, content, error)

app = webapp2.WSGIApplication([('/blog?', BlogFront),
							   ('/blog/([0-9]+)', PostPage),
							    ('/blog/newpost', NewPost), 
], debug=True)


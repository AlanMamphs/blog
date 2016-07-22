import webapp2
import jinja2
import os
from google.appengine.ext import db
from google.appengine.api import users
import string
import hmac
import hashlib
import re
import random


SECRET = 'imhosecret'


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

# define regex filters for username, password and email validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}")
EMAIL_RE = re.compile(r"^[\S]+@+[\S]+\.+[\S]+$")

# USER VALIDATION METHODS
# define method to validate username
def valid_username(username):
	return username and USER_RE.match(username) 
# define method to validate password
def valid_password(password):
	return password and PASS_RE.match(password)
# define method to validate email
def valid_email(email):
	return not email or EMAIL_RE.match(email)

# HMAC HASHING METHODS FOR COOKIES
# create hmac hash using secret message
def make_hash(s):
	return hmac.new(SECRET, s).hexdigest()
# create a pair of string and its hash
def create_hash(s):
	return '%s|%s'%(s, make_hash(s))
# split a pair of string and its hash and check if correct
def validate_hash(h):
	s = h.split('|')[0]
	if create_hash(s)==h:
		return s

# HASHLIB HASHING METHODS USING SALT
# method to create salt from 5 random string letters
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))
# create a pair of salt and new hash 
def make_pw_hash(name, pw, salt = None): # salt should not be created with each function call
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest() 
    return '%s,%s' % (salt, h)
# split a pair of salt and its hash and check if correct
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

class Handler(webapp2.RequestHandler):
	"""Basic Handler abstracted from webapp2 lib"""
	
	# defining shortcut function for response.out.write 
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
	
	# FOR JINJA2 ENVIRONMENT
	# defining template rendering methods by jinja2 lib 
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
	
	# METHODS RELATED WITH COOKIES
	# set secure cookies
	def set_hashed_cookies(self, cookie, cookie_val):
		new_cookie_val = create_hash(cookie_val)
		self.response.headers.add_header('Set-Cookie',
			 '%s=%s; Path=/'%(cookie, new_cookie_val))
	# check if cookie is valid
	def reading_cookie(self, cookie):
		cookie_val = self.request.cookies.get(cookie)
		return cookie_val and validate_hash(cookie_val)
	# set cookie value for logged in user
	def login_cookies(self, user):
		self.set_hashed_cookies('user-id', str(user.key().id()))
	# logout, clearing cookie values
	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user-id=; Path=/')
	# query user from User class by id 
	# check against cookie value
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		user_id =  self.reading_cookie('user-id')
		self.user = user_id and User.by_id(int(user_id))


# USER OBJECT WITH HANDLERS

# set up an instance of Key object as a parent key
def user_key(username='default'):
	return db.Key.from_path('users', username)

class User(db.Model):
	"""Models users entry with username, password, 
	email and date of registration"""
	username =  db.StringProperty(required=True)
	password = db.StringProperty(required=True)
	email = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	
	# DEFINING METHODS FOR the CLASS
	# query by id
	@classmethod 
	def by_id(cls, user_id):
		return cls.get_by_id(user_id, parent=user_key())
	# query by name from inherited User class
	@classmethod
	def by_name(cls, username):
		u = db.GqlQuery('SELECT * FROM User WHERE' + 
			' username = :1', username).get()
		return u
	# create entry before putting to datastore
	@classmethod 
	def register(cls, username, password, email):
		password_hash = make_pw_hash(username, password)
		return cls(parent=user_key(),
					username=username,
					password=password_hash,
					email=email)
	# validate login input against stored in the class
	@classmethod
	def login_cls(cls, username, pw):
		u = cls.by_name(username)
		if u and valid_pw(username, pw, u.password):
			return u

class Logout(Handler):
	""" Handler used to clear cookie values and redirect to main page"""
	""" On get request, clear cookies and redirect"""
	def get(self):
		self.logout()

		self.redirect('/')

class Welcome(Handler):
	def get(self):
		self.render('welcome.html')
	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		
		## TO DO login and login should be named differently
		u = User.login_cls(username, password)
		if u: # if exists set cookies and redirect to blog
			self.login_cookies(u)
			self.redirect('/blog')
		else: # render login page with error message
			self.redirect('/login')

		have_error = False
		# store values in variables
		self.username_signup = self.request.get('username_signup')
		self.password_signup = self.request.get('password_signup')
		self.verify_password = self.request.get('verify_password')
		self.email_signup = self.request.get('email_signup')

		# create a dictionary for values in signup.html
		params = dict(username = self.username_signup,
		             email = self.email_signup)
		# query user by name request and check if exists
		u = User.by_name(username = self.username_signup)
		if u:
			params['error_username_signup'] = "This user already exists"
			params['username'] = signup
			have_error = True
		# validate username
		if not valid_username(self.username_signup):
		    params['error_username_signup'] = "That's not a valid username."
		    have_error = True
		# validate password
		if not valid_password(self.password_signup):
		    params['error_password_signup'] = "That wasn't a valid password."
		    have_error = True
		# validate password match
		elif self.password_signup != self.verify_password:
		    params['error_verify'] = "Your passwords didn't match."
		    have_error = True
		# validate email
		if not valid_email(self.email_signup):
		    params['error_email_signup'] = "That's not a valid email."
		    have_error = True
		# fill in error params
		if have_error:
			self.render('welcome.html', **params)
		# pass in the SignUp handler to the next Register handler
		else:
			self.done()
		def done(self, *a, **b):
			raise NotImplementedError


class Login(Welcome):
	""" Handler used to login existing users """
	# on get request, render login.html
	def get(self):
		self.render('login.html', error_login='Invalid login')
	# on post method check against database values
	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		## TO DO login and login should be named differently
		u = User.login_cls(username, password)
		if u: # if exists set cookies and redirect to blog
			self.login_cookies(u)
			self.redirect('/blog')
		else: # render login page with error message
			self.render('login.html', error_login = 'Invalid login')
		

class RegisterWelcome(Welcome):
	""" Handler used for registering new users into database"""
	# function defined in SignUp handler
	def done(self):
		# instantiate new user
		u=User.by_name(self.username_signup)
		if u: # if exists, render page with error msg
			msg = 'That user already exists.'
			self.render('welcome.html', error_username_signup = msg)
		else: # register, add cookies and redirect
			u = User.register(self.username_signup, self.password_signup, self.email_signup)
			u.put()
			self.login_cookies(u)
			self.redirect('/blog')



# BLOG OBJECT WITH HANDLERS

# set up an instance of Key object as a parent key
def blog_key(name='default'):
	return db.Key.from_path('blog', name)

class Blog(db.Model, Handler):
	"""Models blog entry with subject, content, and 
	created and last modified dates"""
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	userid = db.StringProperty(required=True)
	username = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	likes = db.IntegerProperty(default=0)
	lastmodified = db.DateTimeProperty(auto_now = True)

	# methods for replacing new lines with br tag
	# rendering permalink.html template
	def render(self):
		self._render_txt = self.content.replace('\n', '<br>')
		self.render_str("permalink.html", post = post)
	def render_profile(self):
		self._render_txt = self.content.replace('\n', '<br>')
		self.render_str("profile.html", post = post)
	@classmethod 
	def by_user_id(cls, user_id):
		u = db.GqlQuery('SELECT * FROM Blog WHERE userid = :1', user_id)
		return u
	@classmethod 
	def by_id(cls, post_id):
		return cls.get_by_id(post_id, parent=blog_key())
		
	# query by name from inherited User class
	@classmethod
	def by_name(cls, username):
		u = db.GqlQuery('SELECT * FROM Blog WHERE' + 
			' username = :1', username).get()
		return u
	# create entry before putting to datastore
	

def votes_key(name='default'):
	return db.Key.from_path('votes', name)


class Votes(db.Model):
	username = db.StringProperty()
	postid = db.StringProperty()
	votesid = db.StringProperty()
	likes = db.IntegerProperty(default = 0)
	

	@classmethod
	def by_votesid(cls, votesid):
		v = db.GqlQuery('SELECT * FROM Votes WHERE votesid = :1', votesid)
		return v

class Comments(db.Model):
	username = db.StringProperty()
	postid = db.IntegerProperty()
	commentid = db.StringProperty()
	comment = db.TextProperty()
	created = db.DateTimeProperty(auto_now_add=True)



class BlogFront(Handler):
	""" Handler for retrieving 10 last posts and showing them"""
	
	# queries last 10 posts from datastore and renders them
	def get(self):

		blog = db.GqlQuery('SELECT * FROM Blog ORDER BY created DESC LIMIT 20')
		comments = db.GqlQuery('SELECT * FROM Comments ORDER BY created DESC')
		if self.user:
			self.render('blog.html', blog=blog, logout='Logout', comments=comments)
		else:
			self.redirect('/')

	def post(self):
		# if cookie matches, redirect to blog on post request
		if not self.user:
			self.redirect('/')
		else:
			self.redirect('/blog')
			# requesting user-id cookie and querying
			user_id = self.reading_cookie('user-id')
			user = User.by_id(int(user_id))
			username = user.username
			# Like button submits post id
			post_id = self.request.get('post_id')
			blog = Blog.by_id(int(post_id)) 
			# get comment submittion
			comment = self.request.get('comment')
			if comment:
				comments = Comments(username=username, postid=int(post_id), commentid=username+post_id, comment=comment)
				comments.put()


			# if like was pressed and it is not current user's post
			if post_id and user_id != blog.userid and not comment:
				votes = Votes.all()
				# if there are any entries in Votes table
				if votes.get():						
					votes = Votes.by_votesid(username+post_id).get()
					# if votesid exists
					if votes:
						# if votesid's likes == 0 increment
						if votes.likes==0:
							votes.delete()
							vote = Votes(username=username, postid=post_id, votesid=username+post_id,  likes=1)
							vote.put()
							blog.likes += 1
							blog.put()						
						# else if 1 decrement
						elif votes.likes==1:
							votes.delete()
							vote2 = Votes(username=username, postid=post_id, votesid=username+post_id, likes=0)
							vote2.put()
							blog.likes -= 1 
							blog.put()
					# if votesid doesn't exist, create
					elif not votes:
						vote4 = Votes(username=username, postid=post_id, votesid=username+post_id, likes=1)
						vote4.put()	
						blog.likes += 1	
						blog.put()
				# if no entries in Votes, create
				elif not votes.get():
					vote = Votes(username=username, postid=post_id, votesid=username+post_id, likes=1)
					vote.put()
					blog.likes += 1
					blog.put()




class PostPage(Handler):
	""" Handler for accessing posts from permalink"""
	
	# creates a new Key of kind Blog with post id under parent blog_key
	def get(self, post_id):
		key = db.Key.from_path('Blog', int(post_id), parent =blog_key())
		post = db.get(key) 	# queries the post using created key
		
		# if post doesn't exits return 404 error
		if not post:
			self.error(404)
			return
		# renders permalink.html using jinja2
		self.render('permalink.html', post=post)

class NewPost(Handler):
	""" Handler for creating new posts """
	
	# defining rendering function for new post
	def np_render(self, subject='', content = '', error=''):
		self.render('newpost.html', subject=subject, content=content, error=error)
	# rendering blank newpost.html at request
	def get(self):
		if self.user:
			self.render('newpost.html', logout='Logout')
		else:
			self.redirect('/blog')
	# storing subject and content posted 
	def post(self):
		if not self.user:
			self.redirect('/blog')
		user_id = self.reading_cookie('user-id')
		user = User.by_id(int(user_id))
		username = user.username
		subject = self.request.get('subject')
		content = self.request.get('content')
		# if subject and content exists store it in Blog table
		if subject and content:
			b = Blog(parent=blog_key(), username = username, userid = user_id, subject=subject, content=content)
			b.put()
			self.redirect('/blog/%s'% str(b.key().id()))
		else:
			error = "Subject or Blog is missing."
			self.np_render(subject, content, error)

class Profile(Handler):
	
	def get(self):
		if not self.user:
			self.redirect('/')
		else:
			user_id = self.reading_cookie('user-id')
			user = User.by_id(int(user_id))
			username = user.username
			self.redirect('/profile/%s'% username)






class ProfileHandler(Profile):
	def get(self, user_id):
		if self.user:
			user_id = self.reading_cookie('user-id')
			blog = Blog.by_user_id(user_id)
			self.render('profile.html', blog=blog, logout='Logout')
		else:
			self.redirect('/')
	def post(self, *a):
		if self.user:
			post_id = self.request.get('post_id')
			self.redirect('/editpost/'+post_id)
		else:
			self.redirect('/')





	

class EditPost(ProfileHandler):
	def np_render(self, subject='', content = '', error=''):
		self.render('editpost.html', subject=subject, content=content, error=error)
	# rendering blank newpost.html at request

	def get(self, post_id):
		post = Blog.by_id(int(post_id))
	
		if self.user and post:
			post_subject = post.subject
			post_content = post.content
			self.render('editpost.html', subject = post_subject, content = post_content)
		else:
			self.redirect('/profile')
			
	def post(self, post_id):
		if not self.user:
			self.redirect('/')
		else:
			user_id = self.reading_cookie('user-id')
			user = User.by_id(int(user_id))
			username = user.username
			subject = self.request.get('subject')
			content = self.request.get('content')
			# if subject and content exists store it in Blog table
			if subject and content:
				post = Blog.by_id(int(post_id))
				Blog.delete(post)		
				b = Blog(parent=blog_key(), username = username, userid = user_id, subject=subject, content=content)
				b.put()
				self.redirect('/blog/%s'% b.key().id())
			else:
				error = "Subject or Blog is missing."
				self.np_render(subject, content, error)


# pathes for handlers

app = webapp2.WSGIApplication([('/blog', BlogFront),
							  ('/blog/([0-9]+)', PostPage),
							  ('/newpost', NewPost),
							    # ('/signup', Register),
								('/profile/([A-Za-z]+)', ProfileHandler),
								('/profile', Profile),
								('/', RegisterWelcome),
								('/login', Login),
								('/logout', Logout),
								('/editpost/([0-9]+)', EditPost)
								
], debug=True)


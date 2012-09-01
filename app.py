# -*- encoding: utf-8 -*-
import os
import re
import datetime

from flask import Flask, session, request, url_for, escape, render_template, json, jsonify, flash, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin, AnonymousUser,
                            confirm_login, fresh_login_required)
from flaskext.bcrypt import Bcrypt

from mongoengine import *
from forms import *
import models
from libs.user import *

app = Flask(__name__)
app.debug = True
app.secret_key = os.environ.get('SECRET_KEY')
flask_bcrypt = Bcrypt(app)

#mongolab connection
connect('dwdfall2012', host=os.environ.get('MONGOLAB_URI'))

login_manager = LoginManager()
login_manager.anonymous_user = Anonymous
login_manager.login_view = "login"
login_manager.login_message = u"Please log in to access this page."
login_manager.refresh_view = "reauth"

@login_manager.user_loader
def load_user(id):
	if id is None:
		redirect('/login')

	user = User()
	user.get_by_id(id)
	if user.is_active():
		return user
	else:
		return None

login_manager.setup_app(app)


@app.route('/')
def index():
	templateData = {}

	post = models.Post()
	post.title = "123123"
	post.save()


	return render_template('index.html', **templateData)
    #return 'Hello World!'


@app.route('/styleguide')
def style_guide():
	return render_template('style_guide.html')

# @app.route("/register", methods=["GET","POST"])
# def register():
# 	registerForm = RegisterForm(csrf_enabled=True)

# 	if request.method == 'POST' and registerForm.validate():
# 		email = request.form['email']
		
# 		# generate password hash
# 		password_hash = flask_bcrypt.generate_password_hash(request.form['password'])
		
# 		# prepare User
# 		user = User(email,password_hash)
# 		print user

# 		try:
# 			user.save()
# 			if login_user(user, remember="no"):
# 				flash("Logged in!")
# 				return redirect(request.args.get("next") or url_for("index"))
# 			else:
# 				flash("unable to log you in")

# 		except:
# 			flash("unable to register with that email address")
# 			app.logger.error("Error on registration - possible duplicate emails")
	
# 	# prepare registration form			
# 	registerForm = RegisterForm(csrf_enabled=True)
# 	templateData = {

# 		'form' : registerForm
# 	}

# 	return render_template("/auth/register.html", **templateData)

@app.route('/admin', methods=["GET"])
@login_required
def admin_main():
	return "inside admin"


@app.route('/admin/entry', methods=["GET","POST"])
@login_required
def admin_create_entry():
	if request.method == "POST":

		entryData = {
			'title' : request.form.get('title',''),
			'url_title' : request.form.get('url_title',''),
			'description' : request.form.get('description',''),
			'published' : True if request.form['published'] == "true" else False,
			'github_url' : request.form.get('github_url',None),
			'demo_url' : request.form.get('demo_url',None),
			'content' : request.form.get('content'),
			'assignment' : request.form.get('assignment'),
			'class_date' : datetime.datetime.strptime(request.form.get('class_date'), "%Y-%m-%d")
		}
		print entryData

		entry = models.ClassNote(**entryData)
		
		try:
			entry.save()
			return "saved"

		except ValidationError:
			app.logger.error(ValidationError.errors)
			return "error on saving document"
		

	return render_template('/admin/content_edit.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST" and "email" in request.form:
        email = request.form["email"]
        userObj = User()
        user = userObj.get_by_email_w_password(email)
     	if user and flask_bcrypt.check_password_hash(user.password,request.form["password"]) and user.is_active():
			remember = request.form.get("remember", "no") == "yes"

			if login_user(user, remember=remember):
				flash("Logged in!")
				return redirect(request.args.get("next") or url_for("index"))
			else:
				flash("unable to log you in")

    return render_template("/auth/login.html")


@app.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    if request.method == "POST":
        confirm_login()
        flash(u"Reauthenticated.")
        return redirect(request.args.get("next") or url_for("index"))
    
    templateData = {}
    return render_template("/auth/reauth.html", **templateData)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("index"))





if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

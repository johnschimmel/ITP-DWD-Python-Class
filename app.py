# -*- encoding: utf-8 -*-
import os
import re

from flask import Flask, session, request, url_for, escape, render_template, json, jsonify, flash, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin, AnonymousUser,
                            confirm_login, fresh_login_required)
from flaskext.bcrypt import Bcrypt

from mongoengine import *


app = Flask(__name__)

@app.route('/')
def hello():
	templateData = {}

	return render_template('index.html', **templateData)
    #return 'Hello World!'

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

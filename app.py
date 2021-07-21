from flask import Flask, render_template, jsonify, request, redirect, session
from flask_session import Session
from flask_pymongo import PyMongo
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
import pymongo
import os
from config import Config, db
import datetime
import jwt
import bson
from functools import wraps
from passlib.hash import pbkdf2_sha256
from datetime import datetime, timezone, timedelta
import pytz
from werkzeug.utils import secure_filename
from uuid import uuid4

app = Flask(__name__)
app.config.from_object(Config)

mongo = PyMongo(app)

Session(app)

################Token Decorator#########################

SECRET_KEY = app.config['SECRET_KEY']

def token_required(something):
    @wraps(something)
    def wrap_token(*args, **kwargs):
        try:
            token_passed = request.headers['TOKEN']
            if request.headers['TOKEN'] != '' and request.headers['TOKEN'] != None:
                try:
                    data = jwt.decode(token_passed, SECRET_KEY, algorithms=['HS256'])
                    return something(data['user_id'], *args, **kwargs)
                except jwt.exceptions.ExpiredSignatureError:
                    return_data = {
                        "error": "1",
                        "message": "Token has expired"
                        }
                    return jsonify(return_data)
                except Exception as e:
                    return_data = {
                        "error": "1",
                        "message": "Invalid Token"
                    }
                    return jsonify(return_data)
            else:
                return_data = {
                    "error" : "2",
                    "message" : "Token required",
                }
                return jsonify(return_data)
        except Exception as e:
            print(e)
            return_data = {
                "error" : "3",
                "message" : "An error occured",
                "d_message" : str(e)
                }
            return jsonify(return_data)
    return wrap_token
#########Require Login#################################################
def login_required(something):
    @wraps(something)
    def wrap_login(*args, **kwargs):
        if session['logged_in']:
            return something(session['logged_in_id'], *args, **kwargs)
        else:
            return redirect('/')
    return wrap_login

########################################################################
#########################Forms##########################################
########################################################################
class LoginForm(FlaskForm):
    username = StringField("Username :", validators = [DataRequired()])
    password = PasswordField("Password :", validators = [DataRequired()])
    submit = SubmitField("Log In")

class SignupForm(FlaskForm):
    username = StringField("Username :", validators = [DataRequired()])
    email = StringField("Email :", validators = [DataRequired(), Email()])
    password = PasswordField("Password :", validators = [DataRequired()])
    confirm_password = PasswordField("Confirm Password :", validators = [DataRequired(), EqualTo('password')])
    submit = SubmitField("Sign Up")
########################################################################
#########################Routes#########################################
########################################################################
@app.route('/about')
@app.route('/')
def about():
    return render_template('index.html')

@app.route('/upload')
def upload():
    return render_template('upload.html')

@app.route('/forum')
def forum():
    return render_template('forum.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/main')
@login_required
def main(user_id):
    users = db['users']
    user = users.find_one({'_id': bson.ObjectId(session['logged_in_id'])})
    return render_template("main.html", user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        users = db['users']
        result = users.find_one({
            'username': login_form.username.data,
        })
        if result != None and pbkdf2_sha256.verify(login_form.password.data, result['password_hash']):
            session['logged_in'] = True
            session['logged_in_id'] = result['_id']
            return redirect('/main')
    return render_template("login.html", login_form=login_form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    signup_form = SignupForm()
    if signup_form.validate_on_submit():
        users = db['users']
        dt_now = datetime.now(tz=timezone.utc)
        user = {
            "username": signup_form.username.data,
            "email": signup_form.email.data,
            "password_hash": pbkdf2_sha256.hash(signup_form.password.data),
            "signup_date": dt_now
        }
        users.insert_one(user)
        session['logged_in'] = True
        session['logged_in_id'] = user['_id']
        return redirect('/main')
    return render_template("signup.html", signup_form=signup_form)

@app.route('/logout')
@login_required
def logout(u_is):
    session['logged_in'] = False;
    session['logged_in_id'] = 0
    return redirect('/')

########################################################################
#########################API############################################
########################################################################
@app.route('/api')
def api_index():
    # Very simple
    return_data = {
        'title' : 'API test'
    }
    return jsonify(return_data)

@app.route('/api/auth/token', methods=['POST'])
def api_login():
    # Get details from post request
    username = request.form.get('username')
    password = request.form.get('password')
    users = db['users']
    result = users.find_one({
        'username': username,
    })
    if result != None and pbkdf2_sha256.verify(password, result['password_hash']):
        # Generate exp time and token and return them
        timeLimit= datetime.utcnow() + timedelta(minutes=24*60)
        payload = {"user_id": str(result['_id']),"exp":timeLimit}
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return_data = {
            "error": "0",
            "message": "Successful",
            "token": token,
            "Elapse_time": f"{timeLimit}"
        }
        return jsonify(return_data)
    # IF not correct credentials, give error reponse
    return_data = {
        "error": "1",
        "message": "Invalid username or password"
    }
    return jsonify(return_data)

@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    # Get details from post request
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    users = db['users']
    dt_now1 = datetime.utcnow()
    users.insert_one({
        "username": username,
        "email": email,
        "password_hash": pbkdf2_sha256.hash(password),
        "signup_date": dt_now1
    })
    return_data = {
        "error": "0",
        "message": "Successful",
    }
    return jsonify(return_data)

@app.route('/api/scans/add', methods=["POST"])
@token_required
def api_add(userId):
    scans = db['scans']
    f = request.files['image']
    filename = str(uuid4())
    f_name, f_ext = os.path.splitext(f.filename)
    f.save(os.path.join('static/images/scans/', filename) + f_ext)
    dt_now = datetime.utcnow()
    scans.insert_one({
        "u_id": userId,
        "filename": filename,
        "scandate": dt_now,
    })
    return {"error": "0", "message": "Succesful",}
    
@app.route('/api/wel',methods=['POST'])
@token_required
def api_welcome(userId):
    users = db['users']
    user = users.find_one({'_id': bson.ObjectId(session['logged_in_id'])})
    #Code explains itself (note the new paraameter from the decorator)
    return_data = {
        "error": "0",
        "user": {
            "username": user['username'],
            "email": user['email']
        },
        "message": "You Are verified"
    }
    return jsonify(return_data)

if __name__ == "__main__":
    app.run(debug = True)

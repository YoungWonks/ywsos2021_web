from flask import Flask, render_template, jsonify, request, redirect, session
from flask_session import Session
from flask_pymongo import PyMongo
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, IntegerField, TextAreaField
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
from geopy.geocoders import Nominatim
from flask_minify import minify
import rcssmin
import re

regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

app = Flask(__name__)
minify(app=app,html=True,js=True,cssless=True,static=True)
app.config.from_object(Config)


css_map = {"static/css/theme.css": "static/css/theme.min.css"}
def minify_css(css_map):
    for source, dest in css_map.items():
        with open(source, "r") as infile:
            with open(dest, "w") as outfile:
                outfile.write(rcssmin.cssmin(infile.read()))

mongo = PyMongo(app)

Session(app)

################Token Decorator#########################

SECRET_KEY = app.config['SECRET_KEY']

def token_required(something):
    @wraps(something)
    def wrap_token(*args, **kwargs):
        if 'logged_in' in session.keys():
            if session['logged_in']:
                return something(session['logged_in_id'], *args, **kwargs)
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
                '''except Exception as e:
                    return_data = {
                        "error": "1",
                        "message": "Invalid Token"
                    }
                    return jsonify(return_data)'''
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

#########Scan representation############################################
def create_rep(r):
    reps =  {
        "url":      '/static/images/scans/'+r['filename'],
        "scandate": r['scandate'],
        "position": r['position'],
        "id":       str(r['_id']),
        "upvote":   r['upvote'],
        "title":    r['title'],
        "urgency":  r["urgency"]
    }
    if r["des"]:
        reps["description"] = r["des"]
    return reps

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
    city = StringField("City :")
    submit = SubmitField("Register")

class UploadForm(FlaskForm):
    lat = IntegerField("Latitude", validators=[DataRequired()])
    long = IntegerField("Longitude", validators=[DataRequired()])
    title = StringField("Scan Title", validators=[DataRequired()])
    des = TextAreaField("Scan Description", validators=[DataRequired()])
    image = FileField("Upload File", validators=[DataRequired()])
    urgency = IntegerField("Urgency (Scale of 1 to 10)")
    submit = SubmitField("Submit")
########################################################################
#########################Routes#########################################
########################################################################
@app.route('/')
def about():
    return render_template('index.html')


@app.route('/upload', methods=["GET","POST"])
# @login_required
def upload():
    # if session["logged_in"] is not True:
    #     return redirect("/login")
    upload_form = UploadForm()
    if request.method == "POST":
        scans = db['scans']
        f = request.files['image']

        urgency = request.form.get('urgency', 0)
        dt_now = datetime.utcnow()
        lat = float(request.form.get('lat'))
        long = float(request.form.get('long'))
        filename = secure_filename(str(uuid4()))
        print(f.mimetype)
        filename = filename + ".jpeg"

        title = request.form.get('title')
        des = request.form.get('des', None)
        f.save(os.path.join('static/images/scans/', filename))
        dt_now = datetime.utcnow()
        scans.insert_one({
            "u_id": session['logged_in_id'],
            "filename": filename,
            "scandate": dt_now,
            "position": {
                "lat": lat,
                "long": long
            },
            "loc": {
                "type": "Point",
                "coordinates": [lat, long]
            },
            "upvote": 0,
            "date": datetime.utcnow(),
            "title": title,
            "des": des,
            "urgency": urgency,
            "vote_users": []
        })
    return render_template('upload.html',upload_form=upload_form)
@app.route('/forum')
def forum():
    return render_template('forum.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/main',methods=['GET','POST'])
@login_required
def main(user_id):
    users = db['users']
    user = users.find_one({'_id': bson.ObjectId(session['logged_in_id'])})
    if request.method == "POST":
        if request.get_json().get("changepass"):
            pass
        if request.get_json().get("deleteacc"):
            users.remove({'_id': bson.ObjectId(session['logged_in_id'])})
            return redirect("/logout")
    return render_template("main.html", user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    error = False
    if login_form.validate_on_submit():
        users = db['users']
        result = users.find_one({
            'username': login_form.username.data,
        })
        if result is not None and pbkdf2_sha256.verify(login_form.password.data, result['password_hash']):
            session['logged_in'] = True
            session['logged_in_id'] = str(result['_id'])
            return redirect('/main')
        else:
            error = True
    return render_template("login.html", login_form=login_form, error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    global regex
    signup_form = SignupForm()
    usererror = False
    emailerror = False
    notallowed = False
    if signup_form.validate_on_submit():
        users = db['users']
        dt_now = datetime.now(tz=timezone.utc)
        user = {
            "username": signup_form.username.data,
            "email": signup_form.email.data,
            "password_hash": pbkdf2_sha256.hash(signup_form.password.data),
            "signup_date": dt_now,
            "vote_scans": [],
        }
        if users.find_one({"username":user["username"]}) is not None:
            usererror = True
        elif users.find_one({"email":user["email"]}) is not None or re.match(regex, user["email"]) is False:
            emailerror = True
        else:
            users.insert_one(user)
            session['logged_in'] = True
            session['logged_in_id'] = str(user['_id'])
            return redirect('/main')
    elif signup_form.is_submitted():
        notallowed = True
    return render_template("signup.html", signup_form=signup_form,usererror=usererror,emailerror=emailerror,notallowed=notallowed)

@app.route('/logout')
@login_required
def logout(u_is):
    session['logged_in'] = False
    session['logged_in_id'] = ''
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
    username = request.get_json().get('username')
    password = request.get_json().get('password')
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
            "Elapse_time": f"{timeLimit}",
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
    username = request.get_json().get('username')
    email = request.get_json().get('email')
    password = request.get_json().get('password')
    users = db['users']
    dt_now1 = datetime.utcnow()
    users.insert_one({
        "username": username,
        "email": email,
        "password_hash": pbkdf2_sha256.hash(password),
        "signup_date": dt_now1,
        "vote_scans": [],
    })
    return_data = {
        "error": "0",
        "message": "Successful",
    }
    return jsonify(return_data)

@app.route('/api/scans', methods=["GET","POST"])
@token_required
def api_find(userId):
    scans = db['scans']
    position = request.get_json().get('position', [None, None])
    lat = position[0] if position[0] else 0
    long = position[1] if position[1] else 0
    radius = float(request.get_json().get('range', None))
    scans.create_index([('loc', '2dsphere')])
    result = []
    search = [
        {
            '$geoNear': {
                'near': [ lat, long ],
                'distanceField': 'dist',
                'spherical': True,
            }
        },
        {
            '$match': {
                'u_id': userId,
            },
        },
        {
            '$sort': {
                'dist': 1,
            }
        }
    ]        
    if radius:
        search[0]['$geoNear']['maxDistance'] = radius
    elif not position[0]:
        search = [search[1], {
            '$sort': {
                'vote': -1,
            }
        }]
    result = scans.aggregate(search)
    repairs = []
    for r in result:
        scan = create_rep(r)
        repairs.append(scan)
    return {
        "repairs": repairs,
    }

@app.route('/api/scans/all', methods=["POST"])
def api_find_all():
    scans = db['scans']
    position = request.get_json().get('position', [None, None])
    lat = position[0] if position[0] else 0
    long = position[1] if position[1] else 0
    radius = float(request.get_json().get('range', None))
    scans.create_index([('loc', '2dsphere')])
    result = []
    search = [
        {
            '$geoNear': {
                'near': [ lat, long ],
                'distanceField': 'dist',
                'spherical': True,
            }
        },
        {
            '$sort': {
                'dist': 1,
            }
        }
    ]
    if radius:
        search[0]['$geoNear']['maxDistance'] = radius
    elif not position[0]:
        search = [{
            '$sort': {
                'vote': -1,
            }
        }]
    result = scans.aggregate(search)
    repairs = []
    for r in result:
        scan = create_rep(r)
        repairs.append(scan)
    return {
        "repairs": repairs,
    }

@app.route('/api/scans/forum', methods=["POST"])
def api_find_forum():
    scans = db['scans']
    result = scans.find({}).sort([('upvote', pymongo.DESCENDING)])
    repairs = []
    for r in result:
        scan = create_rep(r)
        repairs.append(scan)
    return {
        "repairs": repairs,
    }

@app.route('/api/scans/vote', methods=["POST"])
@token_required
def api_vote(userId):
    user = db.users.find_one({'_id': bson.ObjectId(userId)})
    id_scan = bson.ObjectId(request.get_json().get("scan_id"))
    scan = db.scans.find_one({'_id': id_scan})
    print(user, scan)
    user_list = scan["vote_users"]
    scan_list = user["vote_scans"]
    user_name = user["username"]
    if user_name in user_list:
        user_list.remove(user_name)
        scan_list.remove(id_scan)
        db.scans.update({'_id': id_scan}, {'$inc': {'upvote': -1}, '$set': {'vote_users': user_list}})
    else:
        user_list.append(user_name)
        scan_list.append(id_scan)
        db.scans.update({'_id': id_scan}, {'$inc': {'upvote': 1}, '$set': {'vote_users': user_list}})
    db.users.update({'_id': user["_id"]}, {'$set': {'vote_scans': scan_list}}) 
    return {
        "error": "0",
        "message": "Successful",
    }

@app.route('/api/scans/upload', methods=["POST"])
@token_required
def api_upload(userId):
    f = request.files['image']
    filename = str(uuid4())
    f.save(os.path.join('static/images/scans/', filename))
    return {"error": "0", "filename":filename,}


@app.route('/api/scans/add', methods=["POST"])
@token_required
def api_add(userId):
    scans = db['scans']
    position = request.get_json().get('position')
    lat = position[0]
    long = position[1]
    filename = request.get_json().get('filename')
    title = request.get_json().get('title')
    des = request.get_json().get('des', None)
    urgency = request.get_json().get('urgency', 0)
    dt_now = datetime.utcnow()
    scans.insert_one({
        "u_id": userId,
        "filename": filename,
        "scandate": dt_now,
        "position": {
            "lat": lat,
            "long": long
        },
        "loc": {
            "type": "Point",
            "coordinates": [lat, long]
        },
        "upvote": 0,
        "date": datetime.utcnow(),
        "title": title,
        "des": des,
        "urgency": urgency,
        "vote_users": [],
    })
    return {"error": "0", "message": "Succesful",}

@app.route('/api/wel',methods=['POST'])
@token_required
def api_welcome(userId):
    users = db['users']
    user = users.find_one({'_id': bson.ObjectId(userId)})
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
    minify_css(css_map)
    app.run(debug = True)

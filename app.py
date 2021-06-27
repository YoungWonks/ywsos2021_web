from flask import Flask, render_template
from flask_session import Session
from flask_pymongo import PyMongo
import pymongo
from datetime import timedelta
import os
from dotenv import load_dotenv

# refers to application_top
APP_ROOT = os.path.join(os.path.dirname(__file__),'.') 
dotenv_path = os.path.join(APP_ROOT, '.env')
load_dotenv(dotenv_path)

app = Flask(__name__)

#loading variables
app.config['DEBUG'] = os.environ.get('DEBUG')
app.config['TESTING'] = os.environ.get('TESTING')
app.config['CSRF_ENABLED'] = os.environ.get('CSRF_ENABLED')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE')
app.config['SESSION_COOKIE_HTTPONLY'] = os.environ.get(
    'SESSION_COOKIE_HTTPONLY')
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get(
    'SESSION_COOKIE_SAMESITE')
app.config['SESSION_TYPE'] = os.environ.get('SESSION_TYPE')
app.config['SESSION_MONGODB_URL'] = os.environ.get('MONGO_URI')
app.config['SESSION_TIME'] = os.environ.get('SESSION_TIME')
app.config['MONGO_URI'] = os.environ.get("MONGO_URI")
app.config['ENV'] = os.environ.get('ENV')
app.config['DOMAIN'] = os.environ.get('DOMAIN')
app.config['SECRET_KEY'] = os.environ.get('SESSION_TYPE')
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT')
app.config['SESSION_TYPE'] = os.environ.get('SESSION_TYPE')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
    minutes=int(os.environ.get('SESSION_TIME')))


mongo = PyMongo(app)

app.config['SESSION_MONGODB'] = pymongo.MongoClient(
    os.environ.get('MONGO_URI'))

Session(app)


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run()

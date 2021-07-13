import os
import pymongo
from dotenv import load_dotenv
from datetime import timedelta

APP_ROOT = os.path.join(os.path.dirname(__file__),'.') 
dotenv_path = os.path.join(APP_ROOT, '.env')
load_dotenv(dotenv_path)
mongodb_sess = pymongo.MongoClient(os.environ.get('MONGO_URI'))
db = mongodb_sess['georepair']

class Config:
    DEBUG = os.environ.get('DEBUG')
    TESTING = os.environ.get('TESTING')
    CSRF_ENABLED = os.environ.get('CSRF_ENABLED')
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE')
    SESSION_COOKIE_HTTPONLY = os.environ.get('SESSION_COOKIE_HTTPONLY')
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE')
    SESSION_TYPE = os.environ.get('SESSION_TYPE')
    SESSION_MONGODB_URL = os.environ.get('MONGO_URI')
    SESSION_TIME = os.environ.get('SESSION_TIME')
    MONGO_URI = os.environ.get("MONGO_URI")
    ENV = os.environ.get('ENV')
    DOMAIN = os.environ.get('DOMAIN')
    SECRET_KEY = os.environ.get('SESSION_TYPE')
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT')
    SESSION_TYPE = os.environ.get('SESSION_TYPE')
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get('SESSION_TIME')))
    SESSION_MONGODB = mongodb_sess

from flask import Flask, render_template, jsonify, request
from flask_session import Session
from flask_pymongo import PyMongo
import pymongo
import os
from config import Config
import datetime
import jwt

app = Flask(__name__)
app.config.from_object(Config)

mongo = PyMongo(app)

Session(app)

################Token Decorator#########################

SECRET_KEY = "asdfdsfansdfkashfjafskdfa;sajfsdkfjas;dlfkasj;dfl"

def token_required(something):
    def wrap():
        try:
            token_passed = request.headers['TOKEN']
            if request.headers['TOKEN'] != '' and request.headers['TOKEN'] != None:
                try:
                    data = jwt.decode(token_passed,SECRET_KEY, algorithms=['HS256'])
                    return something(data['user_id'])
                except jwt.exceptions.ExpiredSignatureError:
                    return_data = {
                        "error": "1",
                        "message": "Token has expired"
                        }
                    return jsonify(return_data)
                except:
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
    return wrap

########################################################################

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api')
def api_index():
    # Very simple
    return_data = {
        'title' : 'API test'
    }
    return jsonify(return_data)

@app.route('/api/login', methods=['POST'])
def api_login():
    # Get details from post request
    username = request.form.get('username')
    password = request.form.get('password')
    if password == "abcdefg":
        # Generate exp time and token and return them
        timeLimit= datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        payload = {"user_id": username,"exp":timeLimit}
        token = jwt.encode(payload,SECRET_KEY)
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
        "message": "Invalid password"
    }
    return jsonify(return_data)

@app.route('/api/wel',methods=['POST'])
@token_required
def api_welcome(userId):
    #Code explains itself (note the new paraameter from the decorator)
    return_data = {
        "error": "0",
        "welcome": "Hello {}".format(userId),
        "message": "You Are verified"
    }
    return jsonify(return_data)

if __name__ == "__main__":
    app.run()

[YoungWonks](https://youngwonks.com) Open Source Project Summer 2021 v0.1

This project is an open source initiative by youngwonks students to put their coding skills to work.
We, at YoungWonks, always believe in contributing towards a good cause in society. The coding skills of our students put us in a place where they can contribute in a way that has a social impact. It is with this in mind, that the students of YoungWonks have decided to engage in a socially beneficial open source coding  real-world production level project. 

## Clone the code repository 
```
$> git clone https://github.com/YoungWonks/ywsos2021_web.git
$> cd ywsos2021_web/
```

## Pre-requisites
```
python > 3.8 must be installed
must add python to the path variable
*mac & linux users may need to use explicitly use 'python3'
```
## Flask Application Structure 
```
.
|──────app.py
|──────config.py
|──────api_test.py
|──────documentation/
|──────static/
|──────templates/
|──────test_cases/
|──────venv/
|──────.gitignore
|──────.env
|──────README.md
|──────requirements.txt
```

## Create the 'venv' virtual environment
```
ywsos2021_web/ $> python3 -m venv venv
ywsos2021_web/ $> source venv/bin/activate
(venv) ywsos2021_web/ $> 
```
## Install required Python packages
```
(venv) ywsos2021_web/ $>  pip install -r requirements.txt
```
## Initializing the Database
create a local mongodb server or a cloud mongodb account  (*if you don't have one.)
Create a database

## Create config variables in the .env file
Create a file named .env 
Add the following config variables to it,
```
###################### .env ######################
DEBUG = True
TESTING = False
CSRF_ENABLED = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'None'
SESSION_TYPE='mongodb'
SESSION_TIME=30
PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
MONGO_URI=<<Add your mongogo db url here>>

ENV = "development"
DOMAIN='http://127.0.0.1:5000'
SECRET_KEY=<<Add your secret key  here>>
SECURITY_PASSWORD_SALT=<<Add your password salt here>>
###################### .env ######################
```
## Create DB tables and populate the roles and users tables
TODO: (venv) ywsos2021_web/ $>  python seed_db.py

## Make the api documentation
```
(venv) ywsos2021_web/ $> cd documentation
(venv) ywsos2021_web/documentation/ $> make html
```

## Start the Flask development web server
(venv) ywsos2021_web/ $> python app.py

## Open the website:
Point your web browser to http://localhost:5000/

## Running the automated tests
(venv) ywsos2021_web/ $> python test_cases/run_tests.py


Authors
YoungWonks

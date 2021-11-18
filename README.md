## Finance API

## Table of contents

-   [General info](#general-info)
-   [Features](#features)
-   [API Endpoints](#api-endpoints)
-   [Technologies](#technologies)
-   [Setup](#setup)

## General info<a name="general-info"></a>

Finance API is a REST API built with Flask & SQLAlchemy to operate CRUD operation on the database. The different routes are described below in the API Endpoint section.

## Features<a name="features"></a>

### User features

User account is only available after the first login with User account authenticated with User JWT

-   Allow user to create an account
-   Allow user to login
-   Allow user to disconnect
-   Allow user to save information in the database
-   Allow the user to update or delete their information (name, password, address, etc…)
-   Allow user to delete their account
-   Allow user to reset their password through Email
-   Allow user to upload a profile picture
-   Allow user to save setting in the database
-   Allow user to update or delete their settings (theme, default currency)

### Admin features

Admin features are only available to Admin account authenticated with Admin JWT

-   Allow admin to get a list of existing users
-   Allow admin to update specific user information
-   Allow admin to update specific user setting
-   Allow admin to delete a specific user
-   Allow admin to create specific user

## API Endpoints<a name="api-endpoints"></a>

After running the server, consult Documentation at :

> http://127.0.0.1:5000/

Admin Endpoints:

-   Return JSON with users
-   Update a user from JSON
-   Delete a user from ID
-   Create a user from JSON

User Endpoints:

-   Login User
-   Send Email to Reset Password
-   Reset Password
-   Register User and send Email to set Password
-   Return User Settings
-   Update User Settings

Database schema:

![DB Screenshot](https://github.com/antoineratat/github_docs/blob/main/finance_api/1.png?raw=true)

## Technologies<a name="technologies"></a>

Project is created with:

-   python v3.9.0
-   astroid v2.4.2
-   bcrypt v3.2.0
-   blinker v1.4
-   certifi v2020.11.8
-   cffi v1.14.3
-   click v7.1.2
-   cloudinary v1.23.0
-   colorama v0.4.4
-   Deprecated v1.2.10
-   Flask v1.1.2
-   Flask-Bcrypt v0.7.1
-   flask-buzz v0.1.15
-   Flask-Cors v3.0.9
-   Flask-JWT-Extended v3.24.1
-   Flask-Mail v0.9.1
-   Flask-SQLAlchemy v2.4.4
-   gunicorn v20.0.4
-   inflection v0.3.1
-   isort v5.6.4
-   itsdangerous v1.1.0
-   Jinja2 v2.11.2
-   lazy-object-proxy v1.4.3
-   MarkupSafe v1.1.1
-   mccabe v0.6.1
-   passlib v1.7.4
-   pendulum v2.1.2
-   psycopg2 v2.8.6
-   py-buzz v1.0.3
-   pycparser v2.20
-   PyJWT v1.7.1
-   pylint v2.6.0
-   python-dateutil v2.8.1
-   pytzdata v2020.1
-   six v1.15.0
-   SQLAlchemy v1.3.20
-   toml v0.10.2
-   urllib3 v1.26.2
-   Werkzeug v1.0.1
-   wrapt v1.12.1

## Setup<a name="setup"></a>

### Import project

```
$ git clone https://github.com/antoineratat/api_finance.git
$ py -3 -m venv venv
$ venv\Script\Activate
$ cd finance_api
$ pip install -r requirements.txt
```

### Create Environnement Variable

```
$ SECRET_KEY = '12345678912345678912345678912312'
$ JWT_SECRET_KEY = '12345678912345678912345678912312'
$ DATABASE_URL = 'postgres://myurl:port/dbname'
$ MAIL_USERNAME = 'address@mail.com'
$ MAIL_PASSWORD = 'mailpassword'
$ MAIL_PORT = 'mailport'
$ MAIL_SERVER = 'mailserver'
$ MAIL_USE_TLS = 'usetls'
```

### Initialize Database

```
$ venv\Script\Activate
$ python
$ from run import db
$ db.create_all()
$ exit()
```

### Run project

```
$ python run.py
```

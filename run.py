from flask import Flask, jsonify, abort, make_response, request, render_template, url_for, redirect
from flask_mail import Message, Mail
import os
import json, urllib.request
import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_bcrypt import Bcrypt
from flask_jwt_extended import ( JWTManager, jwt_required, create_access_token, jwt_refresh_token_required, create_refresh_token, get_jwt_identity, get_jwt_claims)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from flask_cors import CORS

# # --- INFO: LOAD CONFIG VARIABLES ---
# with open('config.json') as config_file:
#     config = json.load(config_file)

# --- INFO: APP CONFIGURATION ---

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SECRET_KEY'] =  os.environ.get('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=7)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=7)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = os.environ.get('MAIL_PORT')
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS')
db = SQLAlchemy(app)
mail = Mail(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

# --- INFO: DATABASE MODEL ---

class User(db.Model):
    id = Column(Integer, primary_key=True)
    email = Column(String(40), unique=True, nullable=False)
    username = Column(String(20), unique=True, nullable=False)
    password = Column(String(200), nullable=False)
    date_created = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)

    first_name = Column(String(40), nullable=False)
    last_name = Column(String(40), nullable=False)
    birthdate = Column(String(10), nullable=True)
    position = Column(String(100), nullable=True)
    education = Column(String(100), nullable=True)
    about_me = Column(String(120), nullable=True)

    address = Column(String(100), nullable=True)
    city = Column(String(40), nullable=True)
    postcode = Column(String(40), nullable=True)
    country = Column(String(40), nullable=True)
    profile_picture = Column(String(250), nullable=True, default='default.jpg')

    def __repr__(self):
        return "ID: {}, email: {}, username: {}, profile_picture: {}".format(self.id, self.email, self.username, self.profile_picture)

    def get_reset_token(self, expires_seconds=1800):
            s = Serializer(app.config['SECRET_KEY'], expires_seconds)
            return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try: 
            user_id = s.loads(token)['user_id']
        except: 
            return None
        return User.query.get(user_id)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'date_created': self.date_created,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'birthdate': self.birthdate,
            'position': self.position,
            'education': self.education,
            'about_me': self.about_me,
            'address': self.address,
            'city': self.city,
            'postcode': self.postcode,
            'country': self.country,
            'profile_picture': self.profile_picture,
        }

class Setting(db.Model):
    id = Column(Integer, primary_key=True)
    style = Column(String(40), nullable=False, default='grey')
    default_currency = Column(String(20), nullable=True, default='USD')
    user_id = Column(Integer, ForeignKey('user.id'), unique=True, nullable=False)

# --- INFO: FUNCTIONS ---

def get_users():
    users = User.query.all()
    # cloudinary.uploader.upload("myimage.jpg")
    return jsonify(users=[user.serialize for user in users])

# --- INFO: ADMIN FUNCTIONS ---

def get_user_id(id):
    user = User.query.get_or_404(id)
    return jsonify(user=user.serialize)

def update_user_id(id, password, first_name, last_name, birthdate, position, education, about_me, address, city, postcode, country, profile_picture):
    user = User.query.get_or_404(id)
    if password:
        user.password = password
    if first_name:
        user.first_name = first_name
    if last_name:
        user.last_name = last_name
    if birthdate:
        user.birthdate = birthdate
    if position:
        user.position = position
    if education:
        user.education = education
    if about_me:
        user.about_me = about_me
    if address:
        user.address = address
    if city:
        user.city = city
    if postcode:
        user.postcode = postcode
    if country:
        user.country = country
    if profile_picture: 
        user.profile_picture = profile_picture
    db.session.add(user)
    db.session.commit()
    return make_response(jsonify({'Updated': 'Updated user with ID: {}'.format(id)}), 200)

def delete_user_id(id):
    user = User.query.get_or_404(id)
    setting = Setting.query.filter_by(user_id=user.id).first()
    db.session.delete(setting)
    db.session.commit()
    db.session.delete(user)
    db.session.commit()
    return make_response(jsonify({'Deleted': 'Removed user with ID {}'.format(id)}), 200)
    
# --- INFO: REACT FUNCTIONS --- 

def update_setting(user_id, content):
    setting = Setting.query.filter_by(user_id=user_id).first()
    style = content.get("color", None)
    default_currency = content.get("default_currency", None)
    if style:
        setting.style = style
    if default_currency:
        setting.default_currency = default_currency

    db.session.add(setting)
    db.session.commit()
    return jsonify({"message": "Settings Updated"}), 200 

def update(username, content):
    user = User.query.filter_by(username=username).first()
    password = content.get("password", None)
    first_name = content.get("first_name", None)
    last_name = content.get("last_name", None)
    birthdate = content.get("birthday", None)
    position = content.get("position", None)
    education = content.get("education", None)
    about_me = content.get("aboutMe", None)
    address = content.get("address", None)
    city = content.get("city", None)
    postcode = content.get("postcode", None)
    country = content.get("country", None)
    profile_picture = content.get("profile_picture", None)

    if password:
        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
    if first_name:
        user.first_name = first_name
    if last_name:
        user.last_name = last_name
    if birthdate:
        user.birthdate = birthdate
    if position:
        user.position = position
    if education:
        user.education = education
    if about_me:
        user.about_me = about_me
    if address:
        user.address = address
    if city:
        user.city = city
    if postcode:
        user.postcode = postcode
    if country:
        user.country = country
    if profile_picture: 
        user.profile_picture = profile_picture
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User Updated"}), 200 

@jwt.user_claims_loader
def add_claims_to_access_token(identity):
    user = User.query.filter_by(username=identity).first()
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name, 
        'profile_picture' : user.profile_picture
    }

def login(username, password):
    if not username: 
        return jsonify({"message": "Missing username in request"}), 400
    if not password: 
        return jsonify({"message": "Missing password in request"}), 400
    user = User.query.filter_by(username=username).first()
    if not user: 
        return jsonify({"message": "User not found"}), 401
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Bad username or password"}), 401
    ret = {
        'access_token': create_access_token(identity=username),
        'refresh_token': create_refresh_token(identity=username),
        'username': username,
    }
    return jsonify(ret), 201

def post(email, username, password, first_name, last_name, birthdate, position, education, about_me, address, city, postcode, country, profile_picture):
    hashed_password = ''
    if password != '':
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user_existing = User.query.filter_by(username=username).first()
    email_existing = User.query.filter_by(email=email).first()
    if email_existing:
        return jsonify({"message": "Email already existing"}), 400
    if user_existing:
        return jsonify({"message": "Username already existing"}), 400

    user = User(email=email, username=username, password=hashed_password, first_name=first_name, last_name=last_name, birthdate=birthdate, position=position, education=education, about_me=about_me, address=address, city=city, postcode=postcode, country=country, profile_picture=profile_picture)
    db.session.add(user)
    db.session.commit()
    user = User.query.filter_by(username=username).first()
    setting = Setting(user_id=user.id)
    db.session.add(setting)
    db.session.commit()
    return jsonify(user=user.serialize)

def delete(username):
    if not username:
        return jsonify({"message": "Missing username in request"}), 400
    user = User.query.filter_by(username=username).first()
    if not user: 
        return jsonify({"message": "User not found"}), 401
    setting = Setting.query.filter_by(user_id=user.id).first()
    db.session.delete(setting)
    db.session.delete(user)
    db.session.commit()
    return make_response(jsonify({'Deleted': 'Removed user with ID {}'.format(id)}), 200)

def user_info(username):
    if not username: 
        return jsonify({"message": "Missing username in request"}), 400
    
    user = User.query.filter_by(username=username).first()

    if not user: 
        return jsonify({"message": "User not found"}), 401

    return jsonify(user=user.serialize)

def send_set_email(user):
    print('send set email')
    token = user.get_reset_token()
    print(token)

    msg = Message('Please activate your account', sender='templars69@mail.com', recipients=[user.email])
    msg.body = f'''To set your password, visit the following link:
{ 'https://react-finance-application.herokuapp.com/auth/set/' + token}

If you did not make this request, simply ignore this email and no changes would be made.

Templars @Financial_App,
'''
    try:
        mail.send(msg)
    except: 
        return jsonify({"message": "Mailbox unavailable invalid SMTP"}), 401


def send_reset_email(user):
    token = user.get_reset_token()

    msg = Message('Password Reset Request', sender='templars69@mail.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{ 'https://react-finance-application.herokuapp.com/auth/reset/' + token}

If you did not make this request, simply ignore this email and no changes would be made.

Templars @Financial_App,
'''
    mail.send(msg)

# --- INFO: ROUTES ---

@app.route('/')
def home():
    return render_template('documentation.html', title='Documentation')

# --- INFO: ADMIN ROUTES ---

@app.route('/api/users', methods=['GET'])
@jwt_required
def usersFunction():
    current_user = get_jwt_identity()
    if not current_user == 'antoine.ratat':
        return jsonify({"message": "Unauthorized Admin only"}), 403
        
    return get_users()

@app.route('/api/user/<id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required
def userFunction(id): 
    if not id: 
        abort(404)

    current_user = get_jwt_identity()
    if not current_user == 'antoine.ratat':
        return jsonify({"message": "Unauthorized Admin only"}), 403

    if request.method == 'GET':
        return get_user_id(id)

    elif request.method == 'PUT':
        content = request.get_json(force=True)
        password = content['password'] if 'password' in content.keys() else ''
        first_name = content['first_name'] if 'first_name' in content.keys() else ''
        last_name = content['last_name'] if 'last_name' in content.keys() else ''
        birthdate = content['birthdate'] if 'birthdate' in content.keys() else ''
        education = content['education'] if 'education' in content.keys() else ''
        position = content['position'] if 'position' in content.keys() else ''
        about_me = content['about_me'] if 'about_me' in content.keys() else ''
        address = content['address'] if 'address' in content.keys() else ''
        city = content['city'] if 'city' in content.keys() else ''
        postcode = content['postcode'] if 'postcode' in content.keys() else ''
        country = content['country'] if 'country' in content.keys() else ''
        profile_picture = content['profile_picture'] if 'profile_picture' in content.keys() else ''
        return update_user_id(id, password, first_name, last_name, birthdate, position, education, about_me, address, city, postcode, country, profile_picture)

    elif request.method == 'DELETE':
        return delete_user_id(id)
       
@app.route('/api/users', methods=['POST'])
@jwt_required
def create_user():
    if not request.is_json: 
        return jsonify({"message": "Missing JSON in request"}), 400

    current_user = get_jwt_identity()
    if not current_user == 'antoine.ratat':
        return jsonify({"message": "Unauthorized Admin only"}), 403
        
    content = request.get_json(force=True)
    email = content.get("email", None)
    username = content.get("username", None)
    password = content.get("password", None)
    first_name = content.get("first_name", None)
    last_name = content.get("last_name", None)

    if not email:
        return jsonify({"message": "Missing Email"}), 400
    if not username:
        return jsonify({"message": "Missing Username"}), 400
    if not last_name:
        return jsonify({"message": "Missing Last name"}), 400
    if not first_name:
        return jsonify({"message": "Missing First name"}), 400
    
    password = content['password'] if 'password' in content.keys() else ''
    birthdate = content['birthdate'] if 'birthdate' in content.keys() else ''
    education = content['education'] if 'education' in content.keys() else ''
    position = content['position'] if 'position' in content.keys() else ''
    about_me = content['about_me'] if 'about_me' in content.keys() else ''
    address = content['address'] if 'address' in content.keys() else ''
    city = content['city'] if 'city' in content.keys() else ''
    postcode = content['postcode'] if 'postcode' in content.keys() else ''
    country = content['country'] if 'country' in content.keys() else ''
    profile_picture = content['profile_picture'] if 'profile_picture' in content.keys() else ''
    return post(email, username, password, first_name, last_name, birthdate, position, education, about_me, address, city, postcode, country, profile_picture)


# --- INFO: REACT JWT ROUTES ---

@app.route('/api/login', methods=['POST'])
def user_login():
    if not request.is_json: 
        return jsonify({"message": "Missing JSON in request"}), 400
    content = request.get_json(force=True)
    username = content.get("username", None)
    password = content.get("password", None)
    return login(username, password)

@app.route('/api/reset', methods=['POST'])
def reset_password():
    if not request.is_json: 
        return jsonify({"message": "Missing JSON in request"}), 400

    email = request.get_json(force=True)
    user = User.query.filter_by(email=email).first()
    if not user: 
        return jsonify({"message": "Email doesn\'t exist"}), 401

    send_reset_email(user)
    return jsonify({"message": "Email Sucessfully sent to "+ email})

@app.route('/api/register', methods=['POST'])
def set_password():
    if not request.is_json: 
        return jsonify({"message": "Missing JSON in request"}), 400
    content = request.get_json(force=True)
    email = content.get("email", None)
    username = content.get("username", None)
    first_name = content.get("first_name", None)
    last_name = content.get("last_name", None)

    if not email:
        return jsonify({"message": "Missing Email"}), 400
    if not username:
        return jsonify({"message": "Missing Username"}), 400
    if not last_name:
        return jsonify({"message": "Missing Last name"}), 400
    if not first_name:
        return jsonify({"message": "Missing First name"}), 400

    user = User.query.filter_by(username=username).first()
    if (user and user.password == ''):
        setting = Setting.query.filter_by(user_id=user.id).first()
        db.session.delete(setting)
        db.session.delete(user)
        db.session.commit()

    password = content['password'] if 'password' in content.keys() else ''
    birthdate = content['birthdate'] if 'birthdate' in content.keys() else ''
    education = content['education'] if 'education' in content.keys() else ''
    position = content['position'] if 'position' in content.keys() else ''
    about_me = content['about_me'] if 'about_me' in content.keys() else ''
    address = content['address'] if 'address' in content.keys() else ''
    city = content['city'] if 'city' in content.keys() else ''
    postcode = content['postcode'] if 'postcode' in content.keys() else ''
    country = content['country'] if 'country' in content.keys() else ''
    profile_picture = content['profile_picture'] if 'profile_picture' in content.keys() else ''
    post(email, username, password, first_name, last_name, birthdate, position, education, about_me, address, city, postcode, country, profile_picture)

    user = User.query.filter_by(username=username).first()
    if not user: 
        return jsonify({"message": "Username has not been properly insert into the database"}), 401

    send_set_email(user)
    return jsonify({"message": "Email Sucessfully sent to "+ email})

@app.route('/api/reset_password', methods=['POST'])
def reset_token():
    if not request.is_json:
            return jsonify({"message": "Missing JSON in request"}), 400

    content = request.get_json(force=True)
    password = content.get("password", None)
    token = content.get("token", None)
    
    if not password:
        return jsonify({"message": "Missing password"}), 400
    if not token:
        return jsonify({"message": "Missing token"}), 400

    user = User.verify_reset_token(token)
    if not user:
        return jsonify({"message": "Invalid Token. Token is either invalid or expired"}), 400
    
    user.password = bcrypt.generate_password_hash(password).decode('utf-8')
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Password Updated"}), 200 

@app.route('/api/user', methods=['GET', 'PUT', 'DELETE'])
@jwt_required
def user_update():
    username = get_jwt_identity()

    if request.method == 'GET':
        return user_info(username)

    if request.method == 'PUT':
        if not request.is_json:
            return jsonify({"message": "Missing JSON in request"}), 400
        content = request.get_json(force=True)
        return update(username, content)

    if request.method == "DELETE":
        if not request.is_json:
            return jsonify({"message": "Missing JSON in request"}), 400
        return delete(username)

@app.route('/api/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200  

@app.route('/api/user/setting', methods=['GET', 'PUT'])
@jwt_required
def user_setting():
    claims = get_jwt_claims()
    if not claims: 
        return jsonify({"message": "Missing Claim in Token"}), 400
    user_id = claims['id']
    if not user_id:
        return jsonify({"message": "Missing User ID in Token"}), 400
    setting = Setting.query.filter_by(user_id=user_id).first()
    if not setting:
        return jsonify({"message": "Missing Settings for user"}), 400

    if request.method == 'GET':
        user_setting = {"style": setting.style, "default_currency": setting.default_currency}
        return jsonify(user_setting), 200

    if request.method == 'PUT':
        if not request.is_json:
            return jsonify({"message": "Missing JSON in request"}), 400
        content = request.get_json(force=True)
        return update_setting(user_id, content)

@app.route('/api/exchange/latest', methods=['GET'])
@jwt_required
def latest():
    exchange_api_key = os.environ.get('EXCHANGE_RATE_API_KEY')
    url = "http://api.exchangeratesapi.io/v1/latest?access_key={}".format(exchange_api_key)
    print(url)
    response = urllib.request.urlopen(url)
    data = response.read()
    dict = json.loads(data)
    print(dict)
    return jsonify(dict), 200

@app.route('/api/exchange/history/<date>', methods=['GET'])
@jwt_required
def history(date):
    if not date: 
        abort(404)
    exchange_api_key = os.environ.get('EXCHANGE_RATE_API_KEY')
    exchange_api_key = os.environ.get('EXCHANGE_RATE_API_KEY')
    url = "http://api.exchangeratesapi.io/v1/{}?access_key={}".format(date, exchange_api_key)
    response = urllib.request.urlopen(url)
    data = response.read()
    dict = json.loads(data)
    return jsonify(dict), 200

if __name__ == '__main__':
    app.run(debug=True)
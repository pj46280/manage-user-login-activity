import uuid
from flask import Flask
from flask import request, jsonify, make_response
from pymongo import MongoClient
from datetime import datetime
from flask_bcrypt import Bcrypt
import configparser
from functools import wraps
import jwt
import json
from bson import json_util

config = configparser.ConfigParser()
config.read('config.ini')
MONGO_CONNECTION_STRING = config.get('SECRETS', 'MONGO_CONNECTION_STRING')
DB_NAME = config.get('MONGO_DB', 'DB_NAME')
COLLECTION_NAME = config.get('MONGO_DB', 'COLLECTION_NAME')
USER_COLLECTION = config.get('MONGO_DB', 'USER_COLLECTION')
LOGIN_COLLECTION = config.get('MONGO_DB', 'LOGIN_COLLECTION')
SECRET = config.get('SECRETS', 'TOKEN_SECRET')
DB_TYPE = config.get('MONGO_DB', 'DB_TYPE')

app = Flask(__name__)
# mongo db
if DB_TYPE == "compass":
    hostname = "localhost"
    port = 27017
    client = MongoClient(hostname, port)
else:
    client = MongoClient(MONGO_CONNECTION_STRING)

db = client[DB_NAME]
collection = db[COLLECTION_NAME]
user_collection = db[USER_COLLECTION]
login_collection = db[LOGIN_COLLECTION]
bcrypt = Bcrypt(app)

# decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, 'secret', algorithms='HS256')
            user = user_collection.find_one({'public_id': data['public_id']})
        except Exception as e:
            return jsonify({'message': 'Token is invalid'}), 401
        # print(f"User - {user}")
        return f(user, *args, **kwargs)
    return decorated
    
# routes
@app.route('/home', methods=['GET'])
def home():
    # return "<p>Hello World</p>"
    return {
        'Status': "200",
        "Message": "Hello World"
    }

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    print("Received new user data.")
    # if user exists
    user = user_collection.find_one({'username': username})
    if user:
        print(f'User exists')
        return jsonify({'message': 'Username or Email already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    print("Generated password hash.")
    try:
        user = {
            'username': username, 
            'email': email, 
            'password': hashed_password,
            'public_id': str(uuid.uuid4())
        }
        result = user_collection.insert_one(user)
        if result.inserted_id:
            print('New user created successfully!')
            return jsonify({'message': 'User registered successfully'}), 201
        else:
            print("Failed inserting data into db!")
            raise Exception('User object not inserted into db!')
    except Exception as e:
        print(f'Error:\n{str(e)}')
        return jsonify({'error': str(3)}), 400


@app.route('/login', methods=['POST'])
def login():
    print("Logging in...")
    data = request.json
    username = data.get('username')
    password = data.get('password')

    print("Querying for user in db...")
    user = user_collection.find_one({'username': username})
    if not user:
        print("User not found!")
        return jsonify({"message": 'User not found'}), 404

    print("User found!")
    is_valid = bcrypt.check_password_hash(user['password'], password)
    if not is_valid:
        print("Invalid password!")
        return jsonify({'message': 'Incorrect password'}), 401

    print("Generating Token!")
    token = jwt.encode({'public_id': user['public_id']}, SECRET)

    data = {
        'device': str(request.user_agent),
        'loginTime': str(datetime.now()),
        'ipAddr': str(request.remote_addr)
    }
    
    return make_response(jsonify({
        "message": "Login successful", 
        "data": data,
        "token": token
    }), 201)

@app.route('/dashboard', methods=['GET', 'POST'])
@token_required
def dashboard(user):
    users = login_collection.find()
    users = list(users)
    if request.method == "POST":
        # request commming from log in 
        try:
            data_str = request.args.get('userData')
            data = json.loads(data_str)
            current_user = login_collection.find_one({'username': user['username']})
            if current_user:
                response = jsonify({'message': 'User already logged in!', 'users': json_util.dumps(users)})
                return response, 200
            login = {
                'username': user['username'],
                'device': data.get('device'),
                'ipAddress': data.get('ipAddr'),
                'loginTime': data.get('loginTime')
            }
            result = login_collection.insert_one(login)
            if result.inserted_id:
                users = login_collection.find()
                users = list(users)
                response = jsonify({"message": "Data inserted", 'users': json_util.dumps(users)})
                return response, 200
        except Exception as e:
            print(f"Error occured while inserting data!\n{e}")
            return jsonify({'message': 'failed'}), 400
    else:
        print(f"Users - {users}")
        return jsonify({'message': 'Dashboard, list of users', 'users': json_util.dumps(users)})
        

if __name__ == "__main__":
    app.run(debug=True)

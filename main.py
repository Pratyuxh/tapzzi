import json
import os
import ssl
import certifi
import boto3
from flask_pymongo import PyMongo
from pymongo import MongoClient
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from pymongo import MongoClient
from bson.json_util import dumps
from crypt import methods
from flask import Flask, jsonify, request, make_response, render_template, flash, redirect, g, after_this_request
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flasgger import Swagger
from botocore.exceptions import NoCredentialsError


app = Flask(__name__)
cors = CORS(app)
app.config["CORS_HEADERS"] = "Content-Type"
mongo_db_url = os.environ.get("MONGO_DB_CONN_STRING")
client = MongoClient(mongo_db_url)
db = client['tapzzi'] 

connection_string = f"mongodb+srv://pratyush:76m3t4IY0kqh19p8@superminds-cluster-public-f49e7a24.mongo.ondigitalocean.com/admin?authSource=admin&replicaSet=superminds-cluster-public&tls=true"
client = MongoClient(connection_string, tlsCAFile=certifi.where())

app.config['MONGO_URI'] = "mongodb+srv://pratyush:76m3t4IY0kqh19p8@superminds-cluster-public-f49e7a24.mongo.ondigitalocean.com/admin?authSource=admin&replicaSet=superminds-cluster-public&tls=true"
mongo = PyMongo(app)

SWAGGER_URL = '/swagger'  # URL for exposing Swagger UI (without trailing '/')
API_URL = '/static/swagger.json'  # Our API url (can of course be a local resource)

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  # Swagger UI static files will be mapped to '{SWAGGER_URL}/dist/'
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': "Tapzzi"
    },
)

app.register_blueprint(swaggerui_blueprint, url_prefix = SWAGGER_URL)

# Configure JWT
app.config['JWT_SECRET_KEY'] = '854d9f0a3a754b16a6e1f3655b3cfbb5'
jwt = JWTManager(app)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['PROPAGATE_EXCEPTIONS'] = True

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcwMDQ3MTg0NCwianRpIjoiNjg1MDdkZDAtOGZiYS00NTM1LTk0M2UtODE3MDcwODMyODM2IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InVzZXIxIiwibmJmIjoxNzAwNDcxODQ0LCJleHAiOjE3MDA0NzI3NDR9.LwwPvBpOwU6xi6pGAEMUo7KkzFfAZ4S_VYPLrS90k_k'}

# Mock user data for demonstration
users = {
    'user1': {'password': 'password1'},
    "admin": generate_password_hash("admin"),
}

# Token creation route (login)
@app.route('/login', methods=['GET','POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if username in users and users[username]['password'] == password:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# Protected route (CRUD operations)
@app.route('/protected', methods=['GET', 'POST'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# Configure BasicAuth
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@app.route('/')
@auth.login_required
def index():
    return "Hello, {}!".format(auth.current_user())

# Create a User
@app.route('/user', methods=['POST'])
def add_user():
    _json = request.json
    _name = _json['name']
    _email = _json['email']
    _pwd = _json['pwd']

    if _name and _email and _pwd and request.method == 'POST':
        _hashed_password = generate_password_hash(_pwd) 
        id = mongo.db.user.insert_one({'name': _name, 'email': _email, 'pwd': _hashed_password})
        return {"data":"User added successfully"}
    else:
        return {'error':'Not found'}

# Get all games
@app.route('/games', methods=['GET'])
def get_games():
    games = mongo.db.game.find()
    resp = dumps(games)
    return resp

# Get a specific game by ID
@app.route('/game/<id>')
def game(id):
    game = mongo.db.game.find_one({'_id':ObjectId(id)})
    resp = dumps(game)
    return resp

# Create a game
@app.route('/games', methods=['POST'])
def create_game():
    _json = request.json
    _description = _json['description']
    _imageUrl = _json['imageUrl']
    _title = _json['title']
    _iframe = _json['iframe']
    _thumbnail = _json['thumbnail']

    if _description and _imageUrl and _title and _iframe and _thumbnail and request.method == 'POST':
        id = mongo.db.game.insert_one({'description': _description, 'imageUrl': _imageUrl, 'title': _title, 'iframe': _iframe, 'thumbnail': _thumbnail })
        return {"data":"Game Added Successfully"}
    else:
        return {'error':'Game Not Found'}

# Update a game
@app.route('/game/<id>', methods=['PUT'])
def update_game(id):
    _json = request.json
    _id = _json['id']
    _description = _json['description']
    _imageUrl = _json['imageUrl']
    _title = _json['title']
    _iframe = _json['iframe']
    _thumbnail = _json['thumbnail']

    if _description and _imageUrl and _title and _iframe and _thumbnail and request.method == 'PUT':
        mongo.db.game.update_one({'_id': ObjectId(_id['$oid']) if '$oid' in _id else ObjectId(_id)}, {'$set': {'id': _id, 'description': _description, 'imageUrl': _imageUrl, 'title': _title, 'iframe': _iframe, 'thumbnail': _thumbnail}})
        resp = jsonify("Game Updated Successfully")
        resp.status_code = 200
        return resp

# Delete a game
@app.route('/game/<id>', methods=['DELETE'])
def delete_game(id):
    mongo.db.game.delete_one({'_id':ObjectId(id)})
    resp = jsonify("Game Deleted Successfully")
    resp.status_code = 200
    return resp

# Get all tones
@app.route('/tones', methods=['GET'])
def get_tones():
    tones = mongo.db.tones.find()
    resp = dumps(tones)
    return resp

# Get a specific tone by ID
@app.route('/tone/<id>')
def tone(id):
    tone = mongo.db.tones.find_one({'_id':ObjectId(id)})
    resp = dumps(tone)
    return resp

# Create a tone
@app.route('/tones', methods=['POST'])
def create_tone():
    _json = request.json
    _audio = _json['audio']
    _downloads = _json['downloads']
    _description = _json['description']
    _title = _json['title']
    _urlTitle = _json['urlTitle']
    _visited = _json['visited']

    if _audio and _downloads and _description and _title and _urlTitle and _visited and request.method == 'POST':
        id = mongo.db.tones.insert_one({'audio': _audio, 'downloads': _downloads, 'description': _description, 'title': _title, 'urlTitle': _urlTitle, 'visited': _visited})
        return {"data":"Tone Added Successfully"}
    else:
        return {'error':'Tone Not Found'}

# Update a tone
@app.route('/tone/<id>', methods=['PUT'])
def update_tone(id):
    _json = request.json
    _id = id
    _audio = _json['audio']
    _downloads = _json['downloads']
    _description = _json['description']
    _title = _json['title']
    _urlTitle = _json['urlTitle']
    _visited = _json['visited']

    if _audio and _downloads and _description and _title and _urlTitle and _visited and request.method == 'PUT':
        mongo.db.tones.update_one({'_id': ObjectId(_id['$oid']) if '$oid' in _id else ObjectId(_id)}, {'$set': {'audio': _audio, 'downloads': _downloads, 'description': _description, 'title': _title, 'urlTitle': _urlTitle, 'visited': _visited }})
        resp = jsonify("Tone Updated Successfully")
        resp.status_code = 200
        return resp

# Delete a tone
@app.route('/tone/<id>', methods=['DELETE'])
def delete_tone(id):
    mongo.db.tones.delete_one({'_id':ObjectId(id)})
    resp = jsonify("Tone Deleted Successfully")
    resp.status_code = 200
    return resp

# Get all wallpapers
@app.route('/wallpapers', methods=['GET'])
def get_wallpapers():
    wallpapers = mongo.db.wallpapers.find()
    resp = dumps(wallpapers)
    return resp

# Get a specific wallpaper by ID
@app.route('/wallpaper/<id>')
def wallpaper(id):
    wallpaper = mongo.db.wallpapers.find_one({'_id':ObjectId(id)})
    resp = dumps(wallpaper)
    return resp

# Create a wallpaper
@app.route('/wallpapers', methods=['POST'])
def create_wallpaper():
    _json = request.json
    _downloads = _json['downloads']
    _visited = _json['visited']
    _description = _json['description']
    _imageURL = _json['imageURL']
    _title = _json['title']

    if _downloads and _visited and _description and _imageURL and _title and request.method == 'POST':
        id = mongo.db.wallpapers.insert_one({'downloads': _downloads, 'visited': _visited, 'description': _description, 'imageURL': _imageURL, 'title': _title })
        return {"data":"Wallpaper Added Successfully"}
    else:
        return {'error':'Wallpaper Not Found'}

# Update a wallpaper
@app.route('/wallpaper/<id>', methods=['PUT'])
def update_wallpaper(id):
    _json = request.json
    _id = id
    _downloads = _json['downloads']
    _visited = _json['visited']
    _description = _json['description']
    _imageURL = _json['imageURL']
    _title = _json['title']

    if _downloads and _visited and _description and _imageURL and _title and request.method == 'PUT':
        mongo.db.wallpapers.update_one({'_id': ObjectId(_id['$oid']) if '$oid' in _id else ObjectId(_id)}, {'$set': {'downloads': _downloads, 'visited': _visited, 'description': _description, 'imageURL': _imageURL, 'title': _title }})
        resp = jsonify("Wallpaper Updated Successfully")
        resp.status_code = 200
        return resp

# Delete a wallpaper
@app.route('/wallpaper/<id>', methods=['DELETE'])
def delete_wallpaper(id):
    mongo.db.wallpapers.delete_one({'_id':ObjectId(id)})
    resp = jsonify("Wallpaper Deleted Successfully")
    resp.status_code = 200
    return resp

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
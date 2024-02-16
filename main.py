import os
import boto3
from flask_pymongo import PyMongo
from flask_restful import Resource, Api
from pymongo import MongoClient
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
from flask import Flask, Response, jsonify, request, make_response, render_template, flash, redirect, g, after_this_request
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from botocore.exceptions import NoCredentialsError
from bson import ObjectId, json_util
from flask_basicauth import BasicAuth
from flask_bcrypt import Bcrypt

app = Flask(__name__)
jwt = JWTManager(app)
cors = CORS(app)
bcrypt = Bcrypt(app)
auth = HTTPBasicAuth()
app.config["CORS_HEADERS"] = "Content-Type"

# mongodb+srv://pratyush:<replace-with-your-password>@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/tapzzi?tls=true&authSource=admin&replicaSet=superminds-cluster
connection_string = f"mongodb+srv://pratyush:43O86u20v1HPDL9h@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/tapzzi?tls=true&authSource=admin&replicaSet=superminds-cluster" 
client = MongoClient(connection_string)
app.config['MONGO_URI'] = "mongodb+srv://pratyush:43O86u20v1HPDL9h@superminds-cluster-7f2d92d1.mongo.ondigitalocean.com/tapzzi?tls=true&authSource=admin&replicaSet=superminds-cluster"
mongo = PyMongo(app)

db = client['tapzzi'] 
collection = db['users']
collection1 = db['games']
collection2 = db['tones']
collection3 = db['wallpapers']
files_collection = db['files']

auth = HTTPBasicAuth()
basic_auth = BasicAuth(app)
api = Api(app)

SWAGGER_URL = '/swagger'  # URL for exposing Swagger UI (without trailing '/')
API_URL = '/static/swagger.json'  # Our API url (can of course be a local resource)

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  # Swagger UI static files will be mapped to '{SWAGGER_URL}/dist/'
    API_URL,
    config={ 
        'app_name': "Tapzzi",
        'uiversion': 3,
        'supportedSubmitMethods': ['get', 'post', 'put', 'delete'],
        'securityDefinitions': {
            'basicAuth': {
                'type': 'basic',
                'description': 'Basic HTTP Authentication',
            },
        },
        'security': [{'basicAuth': []}],
        'validatorUrl': None
    },
)

app.register_blueprint(swaggerui_blueprint, url_prefix = SWAGGER_URL)

@app.route('/static/swagger.json')
@auth.login_required
def send_swagger_json():
    return app.send_static_file('swagger.json')

# Configure JWT
app.config['JWT_SECRET_KEY'] = '854d9f0a3a754b16a6e1f3655b3cfbb5'
jwt = JWTManager(app)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['PROPAGATE_EXCEPTIONS'] = True

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTcwMDQ3MTg0NCwianRpIjoiNjg1MDdkZDAtOGZiYS00NTM1LTk0M2UtODE3MDcwODMyODM2IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InVzZXIxIiwibmJmIjoxNzAwNDcxODQ0LCJleHAiOjE3MDA0NzI3NDR9.LwwPvBpOwU6xi6pGAEMUo7KkzFfAZ4S_VYPLrS90k_k'
}

class Register(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')  # Default role is 'user'
        if not username or not password:
            return {'message': 'Both username and password are required'}, 400
        if collection.find_one({'username': username}):
            return {'message': 'Username already exists'}, 400
        hashed_password = bcrypt.generate_password_hash(
            password).decode('utf-8')
        collection.insert_one(
            {'username': username, 'password': hashed_password, 'role': role})
        return {'message': 'User registered successfully'}, 201

# Login endpoint for admins

class AdminLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = collection.find_one({'username': username, 'role': 'admin'})
        if not user or not bcrypt.check_password_hash(user['password'], password):
            return {'message': 'Invalid admin credentials'}, 401
        access_token = create_access_token(identity=username)
        return {'access_token': access_token}, 200

# Login endpoint for users

class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = collection.find_one({'username': username, 'role': 'user'})
        if not user or not bcrypt.check_password_hash(user['password'], password):
            return {'message': 'Invalid user credentials'}, 401
        access_token = create_access_token(identity=username)
        return {'access_token': access_token}, 200

api.add_resource(Register, '/register')
api.add_resource(AdminLogin, '/admin/login')
api.add_resource(UserLogin, '/user/login')

blacklist = set()  # Set to store revoked tokens

@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200


@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_data):
    jti = jwt_data['jti']
    return jti in blacklist 

# @app.route('/register', methods=['POST'])
# def register_user():
#     data = request.get_json()

#     if 'username' not in data or 'password' not in data:
#         return jsonify({'error': 'Username and password are required'}), 400

#     username = data['username']
#     password = data['password']

#     existing_user = mongo.db.users.find_one({'username': username})
#     if existing_user:
#         return jsonify({'error': 'Username already exists'}), 409

#     hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

#     mongo.db.users.insert_one({
#         'username': username,
#         'password': hashed_password
#     })

#     return jsonify({'message': 'User registered successfully'}), 201

@auth.verify_password
def verify_password(username, password):
    print(f"Received username: {username}, password: {password}")
    user = mongo.db.users.find_one({'username': username})
    if user and bcrypt.check_password_hash(user['password'], password):
        return username
    if user:
        stored_password = user.get('password')
        print(f"Stored password: {stored_password}")
        if bcrypt.check_password_hash(stored_password, password):
            print("Authentication successful")
            return username

    print("Authentication failed")
    return False

@app.route('/')
@auth.login_required
def index():
    return "Hello, {}!".format(auth.current_user())

# # Token creation route (login)
# @app.route('/login', methods=['GET','POST'])
# def login():
#     data = request.get_json()
#     username = data.get('username', None)
#     password = data.get('password', None)

#     user = mongo.db.users.find_one({'username': username})

#     if user and user['password'] == password:
#         access_token = create_access_token(identity=username)
#         return jsonify(access_token=access_token), 200
#     else:
#         return jsonify({'message': 'Invalid credentials'}), 401

validation_rules = {
    "description": "required",
    "imageUrl": "required",
    "title": "required",
    "iframe": "optional",
    "thumbnail": "required",
    }

# Create a game
@app.route('/game', methods=['POST'])
def create_game():
    data = request.get_json()
    # Perform your validations
    validation_errors = validate_data(data, validation_rules)

    if validation_errors:
        # If there are validation errors, send a response with the errors
        return jsonify({"errors": validation_errors}), 400

    inserted_id = collection1.insert_one(data).inserted_id

    # If validation passes, create a response with the desired data
    response_data = {
        "description": data.get("description"),
        "imageUrl": data.get("imageUrl"),
        "title": data.get("title"),
        "iframe": data.get("iframe"),
        "thumbnail": data.get("thumbnail"),
        "_id": str(inserted_id)
        # Add more fields as needed
    }

    return jsonify(response_data)

def validate_data(data, validation_rules):
    errors = []

    for field, rule in validation_rules.items():
        if rule == "required" and not data.get(field):
            errors.append(f"{field} is required.")
        elif rule == "optional" and field in data and not data.get(field):
            errors.append(f"{field} must be optional.")

    return errors

# Update a game
@app.route('/game/<id>', methods=['PUT'])
@jwt_required()
def update_game(id):
    id = ObjectId(id)
    data = request.get_json()
    existing_document = collection1.find_one({"_id": id})

    if existing_document is None:
        return jsonify({"error": "Game not found"}), 404

    response_data = {
        "description": existing_document.get("description"),
        "imageUrl": existing_document.get("imageUrl"),
        "title": existing_document.get("title"),
        "iframe": existing_document.get("iframe"),
        "thumbnail": existing_document.get("thumbnail")
        # Add more fields as needed
    }

    data.pop('_id', None)
    merged_data = {**response_data, **data}
    result = collection1.update_many({"_id": ObjectId(id)}, {"$set": merged_data})

    if result.matched_count == 0:
        return jsonify({"error": "Game not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Game not updated"}), 404
    else:
        return jsonify(response_data)

# Get all games
@app.route('/game', methods=['GET'])
@jwt_required()
def get_games():
    games = list(collection1.find())
    data = []
    for game in games:
        game['_id'] = str(game['_id'])
        data.append(game)
    return jsonify(data)

# Get a specific game by ID
@app.route('/game/<id>')
@jwt_required()
def game(id):
    game = collection1.find_one({'_id':ObjectId(id)})
    if game:
        game["_id"] = str(game["_id"])
        return game
    else:
        return jsonify({"error": "Game Not Found"}), 404

# Delete a game
@app.route('/game/<id>', methods=['DELETE'])
@jwt_required()
def delete_game(id):
    id = ObjectId(id)
    result = collection1.delete_one({"_id": ObjectId(id)})
    if result.deleted_count > 0:
        return jsonify({"message": "Game deleted successfully"})
    else:
        return jsonify({"error": "Game not found or not deleted"}), 404

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE_BYTES = 500 * 500 #10 * 1024 * 1024
DO_SPACES_ENDPOINT = 'https://tapzzi.blr1.digitaloceanspaces.com'  # Replace with your Space URL
DO_ACCESS_KEY = 'DO00H8HLFYNACV6LJ3GP'  # Replace with your DigitalOcean Spaces access key
DO_SECRET_KEY = 'fKbFfbNG2PcuyLCZ79xjePWYjmCP9wGCNdWgfgxCTnY'  # Replace with your DigitalOcean Spaces secret key
DO_BUCKET_NAME = 'tapzzi'  # Replace with your DigitalOcean Spaces bucket name

# Create a connection to DigitalOcean Spaces
# s3 = boto3.client('s3', endpoint_url=DO_SPACES_ENDPOINT, aws_access_key_id=DO_ACCESS_KEY, aws_secret_access_key=DO_SECRET_KEY)
def get_s3_client():
    return boto3.client('s3',
                        aws_access_key_id=DO_ACCESS_KEY,
                        aws_secret_access_key=DO_SECRET_KEY,
                        endpoint_url=DO_SPACES_ENDPOINT)


def allowed_file_size(file):
    return file.content_length <= MAX_FILE_SIZE_BYTES

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_to_digitalocean(file, file_name, device_type, game_id):
    try:
        s3 = get_s3_client()

        # Create a folder with the specified device type
        folder_path = f"{device_type}/"
        file_path = os.path.join(folder_path, file_name)

        # Upload the file to DigitalOcean Spaces
        s3.upload_fileobj(file, DO_BUCKET_NAME, file_path)

        # Get the public URL of the uploaded file
        file_url = f"{DO_SPACES_ENDPOINT}/{DO_BUCKET_NAME}/{file_path}"

        file_info = {
            'filename': file_name,
            'device_type': device_type,
            'url': file_url,
            'game_id': game_id  # Assuming you have an 'id' variable available in your code
        }
        files_collection.insert_one(file_info)

        return file_url

    except NoCredentialsError:
        raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
    except Exception as e:
        raise Exception(str(e))

# Create a game image
@app.route('/game/<id>/image', methods=['POST', 'DELETE'])
@jwt_required()
def upload_and_delete_image(id):
    try:
        file_name = None

        s3 = get_s3_client()

        if request.method == 'POST':
            # Check if the POST request has the file part
            if 'file' not in request.files or 'device_type' not in request.form:
                return jsonify({"error": "No file or device type provided"}), 400

            file = request.files['file']
            device_type = request.form['device_type']

            # If the user does not select a file, the browser submits an empty file without a filename
            if file.filename == '':
                return jsonify({"error": "No selected file"}), 400

            file_name = f"{file.filename}"

            # Upload the file to DigitalOcean Spaces and get the file URL
            file_url = upload_to_digitalocean(file, file_name, device_type, id)

            return jsonify({'message': 'Image uploaded successfully', 'file_url': file_url})

        elif request.method == 'DELETE':

            file_name = request.json.get('filename') or request.args.get('filename')

            if file_name is None:
                return jsonify({"error": "No file specified for deletion"}), 400

            # Delete the file from DigitalOcean Spaces
            s3 = get_s3_client()
            # filename = request.json.get('filename')  # Assuming you send the filename in the request body

            delete_file_from_digitalocean(file_name)

            s3.delete_object(Bucket= DO_BUCKET_NAME, Key=file_name)

            files_collection.delete_one({'filename': file_name})

            return {'message': f'{file_name} deleted successfully'}

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def delete_file_from_digitalocean(file_name):
    try:
        s3 = get_s3_client()
        s3.delete_object(Bucket=DO_BUCKET_NAME, Key=file_name)

    except NoCredentialsError:
        raise Exception('Credentials not available. Check your DigitalOcean Spaces access key and secret key.')
    except Exception as e:
        raise Exception(str(e))

def delete_file_from_mongodb(file_name):
    # Delete the file information from MongoDB
    files_collection.delete_one({'filename': file_name})

# Delete a game image
@app.route('/game/<id>/image/<filename>', methods=['DELETE'])
@jwt_required()
def delete_uploaded_image(id, filename):
    try:
        # Delete the file from DigitalOcean Spaces
        delete_file_from_digitalocean(filename)

        # Delete the file information from MongoDB
        delete_file_from_mongodb(filename)

        return {'message': f'File {filename} deleted successfully'}

    except Exception as e:
        return jsonify({'error': str(e)}), 500

validation_rules2 = {
    "description": "required",
    "audio": "required",
    "downloads": "required",
    "title": "required",
    "urlTitle": "required",
    "visited": "required",
    }

# Create a tone
@app.route('/tone', methods=['POST'])
def create_tone():
    data = request.get_json()
    # Perform your validations
    validation_errors = validate_data(data, validation_rules2)

    if validation_errors:
        # If there are validation errors, send a response with the errors
        return jsonify({"errors": validation_errors}), 400

    inserted_id = collection2.insert_one(data).inserted_id

    # If validation passes, create a response with the desired data
    response_data = {
        "description": data.get("description"),
        "audio": data.get("audio"),
        "downloads": data.get("downloads"),
        "title": data.get("title"),
        "urlTitle": data.get("urlTitle"),
        "visited": data.get("visited"),
        "_id": str(inserted_id)
        # Add more fields as needed
    }

    return jsonify(response_data)

def validate_data(data, validation_rules2):
    errors = []

    for field, rule in validation_rules2.items():
        if rule == "required" and not data.get(field):
            errors.append(f"{field} is required.")
        elif rule == "optional" and field in data and not data.get(field):
            errors.append(f"{field} must be optional.")

    return errors

# Update a tone
@app.route('/tone/<id>', methods=['PUT'])
@jwt_required()
def update_tone(id):
    id = ObjectId(id)
    data = request.get_json()
    existing_document = collection2.find_one({"_id": id})

    if existing_document is None:
        return jsonify({"error": "Tone not found"}), 404

    response_data = {
        "description": existing_document.get("description"),
        "audio": existing_document.get("audio"),
        "downloads": existing_document.get("downloads"),
        "title": existing_document.get("title"),
        "urlTitle": existing_document.get("urlTitle"),
        "visited": existing_document.get("visited")
        # Add more fields as needed
    }

    data.pop('_id', None)
    merged_data = {**response_data, **data}
    result = collection2.update_many({"_id": ObjectId(id)}, {"$set": merged_data})

    if result.matched_count == 0:
        return jsonify({"error": "Tone not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Tone not updated"}), 404
    else:
        return jsonify(response_data)


# Get all tones
@app.route('/tone', methods=['GET'])
@jwt_required()
def get_tones():
    tones = list(collection2.find())
    data = []
    for tone in tones:
        tone['_id'] = str(tone['_id'])
        data.append(tone)
    return jsonify(data)

# Get a specific tone by ID
@app.route('/tone/<id>')
@jwt_required()
def tone(id):
    tone = collection2.find_one({'_id':ObjectId(id)})
    if tone:
        tone["_id"] = str(tone["_id"])
        return tone
    else:
        return jsonify({"error": "Tone Not Found"}), 404

# Delete a tone
@app.route('/tone/<id>', methods=['DELETE'])
@jwt_required()
def delete_tone(id):
    id = ObjectId(id)
    result = collection2.delete_one({"_id": ObjectId(id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Tone deleted successfully"})
    else:
        return jsonify({"error": "Tone not found or not deleted"}), 404

validation_rules3 = {
    "downloads": "required",
    "visited": "required",
    "description": "required",
    "imageURL": "required",
    "title": "required"
    }

# Create a wallpaper
@app.route('/wallpaper', methods=['POST'])
def create_wallpaper():
    data = request.get_json()
    # Perform your validations
    validation_errors = validate_data(data, validation_rules3)

    if validation_errors:
        # If there are validation errors, send a response with the errors
        return jsonify({"errors": validation_errors}), 400

    inserted_id = collection3.insert_one(data).inserted_id

    # If validation passes, create a response with the desired data
    response_data = {
        "downloads": data.get("downloads"),
        "visited": data.get("visited"),
        "description": data.get("description"),
        "imageURL": data.get("imageURL"),
        "title": data.get("title"),
        "_id": str(inserted_id)
        # Add more fields as needed
    }

    return jsonify(response_data)

def validate_data(data, validation_rules3):
    errors = []

    for field, rule in validation_rules3.items():
        if rule == "required" and not data.get(field):
            errors.append(f"{field} is required.")
        elif rule == "optional" and field in data and not data.get(field):
            errors.append(f"{field} must be optional.")

    return errors

# Update a wallpaper
@app.route('/wallpaper/<id>', methods=['PUT'])
@jwt_required()
def update_wallpaper(id):
    id = ObjectId(id)
    data = request.get_json()
    existing_document = collection3.find_one({"_id": id})

    if existing_document is None:
        return jsonify({"error": "Wallpaper not found"}), 404

    response_data = {
        "downloads": existing_document.get("downloads"),
        "visited": existing_document.get("visited"),
        "description": existing_document.get("description"),
        "imageURL": existing_document.get("imageURL"),
        "title": existing_document.get("title")
        # Add more fields as needed
    }

    data.pop('_id', None)
    merged_data = {**response_data, **data}
    result = collection3.update_many({"_id": ObjectId(id)}, {"$set": merged_data})

    if result.matched_count == 0:
        return jsonify({"error": "Wallpaper not found"}), 404
    elif result.modified_count == 0:
        return jsonify({"error": "Wallpaper not updated"}), 404
    else:
        return jsonify(response_data)

# Get all wallpapers
@app.route('/wallpaper', methods=['GET'])
@jwt_required()
def get_wallpapers():
    wallpapers = list(collection3.find())
    data = []
    for wallpaper in wallpapers:
        wallpaper['_id'] = str(wallpaper['_id'])
        data.append(wallpaper)
    return jsonify(data)

# Get a specific wallpaper by ID
@app.route('/wallpaper/<id>')
@jwt_required()
def wallpaper(id):
    wallpaper = collection3.find_one({'_id':ObjectId(id)})
    if wallpaper:
        wallpaper["_id"] = str(wallpaper["_id"])
        return wallpaper
    else:
        return jsonify({"error": "Wallpaper Not Found"}), 404


# Delete a wallpaper
@app.route('/wallpaper/<id>', methods=['DELETE'])
@jwt_required()
def delete_wallpaper(id):
    id = ObjectId(id)
    result = collection3.delete_one({"_id": ObjectId(id)})

    if result.deleted_count > 0:
        return jsonify({"message": "Wallpaper deleted successfully"})
    else:
        return jsonify({"error": "Wallpaper not found or not deleted"}), 404

# apis = [
#     "http://localhost:8080/games",
#     "http://localhost:8080/tones",
#     "http://localhost:8080/wallpapers"
#     # Add more endpoints as needed
# ]

# @app.route('/getAllData', methods=['GET'])
# def get_aggregated_data():
#     aggregated_data = {}

#     # Get a list of all collection names in the database
#     collections = db.list_collection_names()

#     for collection_name in collections:
#         # Retrieve all documents from the current collection
#         collection_data = list(db[collection_name].find())
#           # Convert ObjectId to string in each document
#         for entry in collection_data:
#             entry['_id'] = str(entry['_id'])
#         aggregated_data[collection_name] = collection_data
        
#     return jsonify(aggregated_data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
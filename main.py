import json
import os
from flask import Flask, jsonify, request, make_response, render_template, flash, redirect
from flask_pymongo import PyMongo
from pymongo import MongoClient
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from pymongo import MongoClient
from bson.json_util import dumps


app = Flask(__name__)
mongo_db_url = os.environ.get("MONGO_DB_CONN_STRING")

client = MongoClient(mongo_db_url)
db = client['tapzzi'] 

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

games = [
    {
        'id': 1,
        'description':'Explore and play bite-sized games anytime, anywhere-no downloads, just pure entertainment on the go!',
        'imageUrl': 'www.xyz.com',
        'title': 'Games',
        'iframe': 'http://xyz.com/index.html',
        'thumbnail': '/assets/games/cricket.jpg'
    }
]

# Get all games
@app.route('/games', methods=['GET'])
def get_games():
    return games


# Get a specific game by ID
@app.route('/games/<int:id>', methods=['GET'])
def get_game(id):
    for game in games:
        if game['id']==id:
            return game

    return {'error':'Game not found'}

# Create a game
@app.route('/games', methods=['POST'])
def create_game():
    new_game={'id':len(games)+1, 'description':request.json['description'], 'imageUrl':request.json['imageUrl'], 'title': request.json['title'], 'iframe': request.json['iframe'], 'thumbnail': request.json['thumbnail'] }
    games.append(new_game)
    return new_game


# Update a game
@app.route('/games/<int:id>', methods=['PUT'])
def update_game(id):
    for game in games:
        if game['id']==id:
            game['description']=request.json['description']
            game['imageUrl']=request.json['imageUrl']
            game['title']=request.json['title']
            game['iframe']=request.json['iframe']
            game['thumbnail']=request.json['thumbnail']
            return game 
    return {'error':'Game not found'}

# Delete a game
@app.route('/games/<int:id>', methods=['DELETE'])
def delete_game(id):
    for game in games:
        if game['id']==id:
            games.remove(game)
            return {"data":"Game Deleted Successfully"}

    return {'error':'Game not found'}

tones = [
    {
        'id': 1,
        'description': 'Explore and play bite-sized games anytime, anywhere-no downloads, just pure entertainment on the go!',
        'audio':'https://xyz.com',
        'Downloads': '5.5k',
        'title': 'Three Little Birds',
        'urlTitle': 'three-little-birds',
        'visited': '10.5k'
    }
]

# Get all tones
@app.route('/tones', methods=['GET'])
def get_tones():
    return tones


# Get a specific tone by ID
@app.route('/tones/<int:id>', methods=['GET'])
def get_tone(id):
    for tone in tones:
        if tone['id']==id:
            return tone

    return {'error':'Tone not found'}

# Create a tone
@app.route('/tones', methods=['POST'])
def create_tone():
    new_tone={'id':len(tones)+1, 'audio':request.json['audio'], 'Downloads':request.json['Downloads'], 'description': request.json['description'],
     'title': request.json['title'], 'urlTitle': request.json['urlTitle'], 'visited': request.json['visited']}
    tones.append(new_tone)
    return new_tone


# Update a tone
@app.route('/tones/<int:id>', methods=['PUT'])
def update_tone(id):
    for tone in tones:
        if tone['id']==id:
            tone['audio']=request.json['audio']
            tone['Downloads']=request.json['Downloads']
            tone['description']=request.json['description']
            tone['title']=request.json['title']
            tone['urlTitle']=request.json['urlTitle']
            tone['visited']=request.json['visited']
            return tone 
    return {'error':'Tone not found'}

# Delete a tone
@app.route('/tones/<int:id>', methods=['DELETE'])
def delete_tone(id):
    for tone in tones:
        if tone['id']==id:
            tones.remove(tone)
            return {"data":"Tone Deleted Successfully"}

    return {'error':'Tone not found'}

wallpapers = [
    {
        'id': 1,
        'description': 'Explore and play bite-sized games anytime, anywhere-no downloads, just pure entertainment on the go!',
        'imageURL':'/assets/wallpaper.png',
        'title': 'wallpapers',
        'downloads': '5k',
        'visited': '9k'
    }
]

# Get all wallpapers
@app.route('/wallpapers', methods=['GET'])
def get_wallpapers():
    return wallpapers


# Get a specific wallpaper by ID
@app.route('/wallpapers/<int:id>', methods=['GET'])
def get_wallpaper(id):
    for wallpaper in wallpapers:
        if wallpaper['id']==id:
            return wallpaper

    return {'error':'Wallpaper not found'}

# Create an wallpaper
@app.route('/wallpapers', methods=['POST'])
def create_wallpaper():
    new_wallpaper={'id':len(wallpapers)+1, 'downloads':request.json['downloads'], 'visited':request.json['visited'], 'description': request.json['description'], 'imageURL': request.json['imageURL'],'title': request.json['title'] }
    wallpapers.append(new_wallpaper)
    return new_wallpaper

# Update an wallpaper
@app.route('/wallpapers/<int:id>', methods=['PUT'])
def update_wallpaper(id):
    for wallpaper in wallpapers:
        if wallpaper['id']==id: 
            wallpaper['downloads']= request.json['downloads'], 
            wallpaper['visited']= request.json['visited'], 
            wallpaper['description']= request.json['description'], 
            wallpaper['imageURL']= request.json['imageURL'],  
            wallpaper['title']= request.json['title']
            return  
    return {'error':'Wallpaper not found'}

# Delete a wallpaper
@app.route('/wallpapers/<int:id>', methods=['DELETE'])
def delete_wallpaper(id):
    for wallpaper in wallpapers:
        if wallpaper['id']==id:
            wallpapers.remove(wallpaper)
            return {"data":"Wallpaper Deleted Successfully"}

    return {'error':'Wallpaper not found'}

# Run the flask App
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
#   app.run(debug=True)
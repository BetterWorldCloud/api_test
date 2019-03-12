from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy


app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.similarityDb
users = db["Users"]

def UserExit(username):
    retUserCount = users.find({"username":username}).count()
    if retUserCount == 0:
        return False
    return True

class Register(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]

        if(UserExit(username)):
            retJson = {
               "status": 301,
               "msg": "Invalid username"
            }
            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        users.insert(
          {
             "username":username,
             "password":hashed_pw,
             "tokens": 6
          }
        )
        retJson = {
           "status": 200,
           "msg": "You successfully signed up"
        }
        return jsonify(retJson)

def verifyPw(username, password):
    hashedPw = users.find({"username":username})[0]["password"]
    if bcrypt.hashpw(password.encode('utf8'), hashedPw) == hashedPw:
        return True
    return False


def countTokens(username):
    num_tokens = users.find({"username":username})[0]["tokens"]
    return num_tokens

class Detect(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        text1 = postedData["text1"]
        text2 = postedData["text2"]

        if UserExit(username) == False:
            retJson = {
              "status": 301,
              "msg": "Invalid username"
            }
            return jsonify(retJson)

        correct_pw = verifyPw(username, password)
        if not correct_pw:
            retJson = {
               "status": 302,
               "msg": "Invalid password"
            }
            return jsonify(retJson)

        num_tokens = countTokens(username)
        if num_tokens <= 0:
            retJson = {
               "status": 303,
               "msg": "You do not have sufficient tokens"
            }
            return jsonify(retJson)

        nlp = spacy.load('en_core_web_sm')

        text1 = nlp(text1)
        text2 = nlp(text2)

        ratio = text1.similarity(text2)

        retJson = {
           "status": 200,
           "similarity": ratio,
           "msg": "Similarity score calculated successfully"
        }

        users.update(
            {
               "username": username
            },
            {
              "$set":{"tokens": num_tokens -1
            }
        })
        return jsonify(retJson)

api.add_resource(Register, '/register')
api.add_resource(Detect, '/detect')

if __name__ == '__main__':
    app.run(host="0.0.0.0")

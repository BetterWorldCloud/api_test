from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")

db = client.mySentenceDb
users = db["users"]

class Register(Resource):
    def post(self):
        try:
            postedData = request.get_json()
            username = postedData["username"]
            password = postedData["password"]

            hashed_pw = bcrypt.hashpw(password.encode('utf8'),bcrypt.gensalt())
            users.insert({
               "username": username,
               "password": hashed_pw,
               "sentence":"",
               "tokens":8
            })

            retJSON = {
               "status": 200,
               "msg": "You successfully signed up for the API"
            }
            return jsonify(retJSON)
        except:
            return "EXCEPTION REGISTER"

def verifyPw(username, password):
    ret = users.find({"username": username})[0]["password"]
    pw_hashed = bcrypt.hashpw(password.encode('utf8'),ret)
    if pw_hashed == ret:
        return True
    return False

def countTokens(username, password):
    token = users.find({"username": username})[0]["tokens"]
    return token


class Store(Resource):
    def post(self):
        try:
            postedData = request.get_json()
            username = postedData["username"]
            password = postedData["password"]
            sentence = postedData["sentence"]

            correct_wd = verifyPw(username, password)

            if(not correct_wd):
                retJSON = {
                   "status": 302,
                   "msg": "Invalid username/password"
                }
                return jsonify(retJSON)

            num_token = countTokens(username, password)
            if num_token <= 0:
                retJSON = {
                   "status": 301,
                   "msg": "you do not have enough tokens",
                   "tokens": num_token
                }
                return jsonify(retJSON)

            users.update(
                {"username":username},
                {"$set":
                   {
                       "sentence": sentence,
                       "tokens": num_token-1
                    }
                })
            retJSON = {
                "status":200,
                "msg": "Sentence saved successfully",
                "tokens": num_token
            }

            return jsonify(retJSON)
        except:
            return "EXCEPTION STORE"


class Get(Resource):
    def post(self):
        try:
            postedData = request.get_json()
            username = postedData["username"]
            password = postedData["password"]

            correct_wd = verifyPw(username, password)

            if(not correct_wd):
                retJSON = {
                   "status": 302,
                   "msg": "Invalid username/password"
                }
                return jsonify(retJSON)
            num_token = countTokens(username, password)
            if num_token <= 0:
                retJSON = {
                   "status": 301,
                   "msg": "you do not have enough tokens"
                }
                return jsonify(retJSON)

            ret = users.find({"username":username})[0]["sentence"]
            retJSON = {
                "status": 200,
                "msg": ret
            }
            users.update(
                {"username":username},
                {
                   "$set":{"token":num_token-1}
                 })

            return jsonify(retJSON)
        except:
            return "EXCEPTION GET"


api.add_resource(Get, '/get')
api.add_resource(Register, '/register')
api.add_resource(Store,'/store')

if __name__=="__main__":
     app.run(host="0.0.0.0")



"""
client = MongoClient("mongodb://db:27017")

db = client.myDatabase

UserNum = db["UserNum"]

UserNum.insert_one({
   'num_of_users':0
})

class Visit(Resource):
    def get(self):
        postedData = request.get_json()
        prev_num = UserNum.find({})[0]['num_of_users']
        new_num = prev_num + 1
        UserNum.update({}, {"$set":{"num_of_users":new_num}})
        return "Hello user "+ str(new_num)

def checkPostedData(postedData, verb):
    if verb != 'Divide':
        if 'x' not in postedData or 'y' not in postedData:
            return 301
        else:
            return 200
    else:
        if 'y' not in postedData or 'x' not in postedData:
            return 301
        if postedData['y'] == 0:
            return 302
        try:
            test = int(postedData['y'])
            test = int(postedData['x'])
        except:
            return 300
        return 200


class Add(Resource):
    def post(self):
        postedData = request.get_json()
        status_code = checkPostedData(postedData, 'add')
        if status_code != 200:
            retJSON = {
            'Message': 'An error occured',
            'Status Code': status_code
            }
            return jsonify(retJSON)

        x = postedData["x"]
        y = postedData["y"]
        x = int(x)
        y = int(y)
        ret = x + y
        retMap = {
        'Message': ret,
        'Status Code': status_code
        }
        return jsonify(retMap)

class Subtract(Resource):
    def post(self):
        postedData = request.get_json()
        status_code = checkPostedData(postedData, 'Subtract')
        if status_code != 200:
            retMap = {
            'Message': 'An error occured',
            'Status Code': status_code
            }
            return jsonify(retMap)

        x,y = int(postedData['x']), int(postedData['y'])
        z = x - y
        retMap ={
        'Message': z,
        'Status Code': status_code
        }

        return jsonify(retMap)

class Multiply(Resource):
    def post(self):
        postedData = request.get_json()
        status_code = checkPostedData(postedData, 'Subtract')
        if status_code != 200:
            retMap = {
            'Message': "An error occured",
            'Status Code': status_code
            }
            return jsonify(retMap)

        x,y = int(postedData['x']), int(postedData['y'])
        z = x*y
        retMap = {
        "Message": z,
        "Status Code": status_code
        }
        return jsonify(retMap)

class Divide(Resource):
    def post(self):
        postedData = request.get_json()
        status_code = checkPostedData(postedData, 'Divide')
        if status_code != 200:
            retMap = {
            'Message': "An error occured",
            'Status Code': status_code
            }
            return jsonify(retMap)

        x,y = int(postedData['x']), int(postedData['y'])
        z = x*(1.0)/y
        retMap = {
        "Message": z,
        "Status Code": status_code
        }
        return jsonify(retMap)


api.add_resource(Add, "/add")
api.add_resource(Subtract, "/subtract")
api.add_resource(Multiply, "/multiply")
api.add_resource(Divide, "/divide")
api.add_resource(Visit, "/hello")

@app.route('/')
def hello_world():
    return "Hello World"

if __name__=="__main__":
     app.run(host="0.0.0.0")
"""

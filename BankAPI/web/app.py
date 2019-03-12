from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.BankDB # Bank database
users = db["users"] # users collection

def UserExit(username):
    if users.find({"username":username}).count() > 0:
        return True
    return False

def retmap(status, message, bal=None, debt=None):
    retJson = {"status": status,"msg": message}
    if(bal != None):
        retJson["balance"] = bal
    if(debt !=None):
        retJson["debt"] = debt
    return retJson

def verifyPassword(username, password):
    if not UserExit(username):
        return False

    hashedPW = users.find({"username":username})[0]["password"]
    if(bcrypt.hashpw(password.encode('utf8'), hashedPW) == hashedPW):
        return True
    return False

def cashWithUser(username):
    if not UserExit(username):
        return False
    bal = users.find({"username":username})[0]["balance"]
    return bal

def debtWithUser(username):
    if not UserExit(username):
        return False
    debt = users.find({"username":username})[0]["debt"]
    return debt

def updateAccount(username, balance):
    users.update({"username":username}, {"$set": {"balance":balance}})

def updateDebt(username, debt):
    users.update({"username":username}, {"$set": {"balance":debt}})

def setUpBankAcc():
    if users.find({"username":"BANK"}).count() == 0:
        users.insert(
            {
                "username": "BANK",
                "password":12345,
                "balance":0,
                "debt":0
            })
        return True
    return False

class SetUpBank(Resource):
    def post(self):
        if setUpBankAcc():
            bankMoney = cashWithUser("BANK")
            return jsonify(retmap(200, 'Bank Acc addded', bankMoney))

        bankMoney = cashWithUser("BANK")
        return jsonify(retmap(301, 'Bank Acc already exits', bankMoney))



class Register(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        bal = postedData["balance"]
        debt = postedData["debt"]

        if UserExit(username):
            return jsonify(retmap(301,"Invalid Username"))
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        param = {
              "username":username, "password":hashed_pw,
              "balance":bal, "debt":debt
            }
        users.insert(param)
        msg = "User successfully registered"
        return jsonify(retmap(200, msg, bal, debt))

def isValueInteger(val):
    try:
        val = int(val)
        if val > 0:
            return True
        return False
    except:
        return False

class Add(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        bal = postedData["add_cash"]
        debt = postedData["debt"]

        if not UserExit(username):
            return jsonify(retmap(301, "Invalid username"))
        if not verifyPassword(username, password):
            return jsonify(retmap(302, "Invalid password"))
        if not isValueInteger(bal):
            return jsonify(retmap(304, "Deposit not accepted."))

        currentCash = cashWithUser(username)
        balance = bal + currentCash -1

        bankMoney = cashWithUser("BANK")
        updateAccount("BANK", bankMoney+1)

        updateAccount(username, balance)
        cash = cashWithUser(username)
        debt = debtWithUser(username)

        msg = str(bal-1) +' successfully deposited in your account.'
        return jsonify(retmap(200, msg, cash, debt))

class Transfer(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        to       = postedData["to"]
        amount   = postedData["amount"]

        if not UserExit(username):
            return jsonify(retmap(301, "Invalid username"))
        if not verifyPassword(username, password):
            return jsonify(retmap(302, "Invalid password"))
        if not isValueInteger(amount):
            return jsonify(retmap(304, "Deposit not accepted."))
        if(UserExit(to) == False):
            msg = to + ' does not exit'
            return jsonify(retmap(301, msg))
        if(isValueInteger(amount) == False):
            return jsonify(retmap(304, "Deposit not accepted."))

        updateAccount(to, amount)
        return jsonify(retmap(200, "Transfer is successfully."))


class Balance(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]

        if not UserExit(username):
            return jsonify(retmap(301, 'Invalid username'))
        if verifyPassword(username, password) == False:
            return jsonify(retmap(302, 'Invalid Password'))

        bal = cashWithUser(username)
        return jsonify(retmap(200,'Balance successfully checked',bal))




api.add_resource(SetUpBank, '/bank')
api.add_resource(Register, '/register')
api.add_resource(Add, '/add')
api.add_resource(Transfer, '/transfer')
api.add_resource(Balance, '/balance')

if __name__ =='__main__':
    app.run(debug=True, host='0.0.0.0', port='5000')

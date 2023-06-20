import pymongo
from pymongo import MongoClient
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

uri = 'mongodb+srv://21520518:0R29AdJKqko34Ulj@otpbaseaes.zk1anvo.mongodb.net/?retryWrites=true&w=majority'
client = MongoClient(uri, server_api=ServerApi('1'))
db = client['Data']
collection = db['Users']

data = collection.find()  # Modify the query as per your requirements

for document in data:
    print(document)

client.close()  # Close the MongoDB client connection

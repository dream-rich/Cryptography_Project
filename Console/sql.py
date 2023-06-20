import pymongo
from pymongo import MongoClient

client = MongoClient('https://ap-southeast-1.aws.data.mongodb-api.com/app/data-wwzqj/endpoint/data/v1/action/')  # Connect to MongoDB client
db = client['Data']
collection = db['Users']

data = collection.find()  # Modify the query as per your requirements

for document in data:
    print(document)

client.close()  # Close the MongoDB client connection

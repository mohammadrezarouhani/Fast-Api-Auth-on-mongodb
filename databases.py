from pymongo import MongoClient
from decouple import config

client = MongoClient(config('MONGO_URI'))
db = client[config('MONGO_DB')]
users_collection = db['users']
black_list_collection = db['balck_list']

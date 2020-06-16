from pymongo import MongoClient

source = MongoClient("")
target = MongoClient("")

target["test"]["user"].insert_many(list(source["test"]["user"].find()))
target["test"]["team"].insert_many(list(source["test"]["team"].find()))
target["test"]["stage"].insert_many(list(source["test"]["stage"].find()))

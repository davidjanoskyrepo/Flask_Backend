import os
from pymongo import MongoClient
import mongomock

class MongoEntry():
    DATABASE_NAME = "EE461L_Final_Project_DB"
    DATABASE_HOST = os.environ.get('MONGO_DB_URI')
    MOCK = (os.getenv("MOCK", "False") == "True")

    DATABASE_USERNAME = "EE461L_Database_Username"
    DATABASE_PASSWORD = "EE461L_Database_Password"

    def __init__(self, collection_name):
        try:
            if self.MOCK == True:
                # Mock the backend db if envion set
                print("[+] Running client as mock!")
                self.my_client = mongomock.MongoClient()
            else:
                print("[+] Running client as hosted!")
                self.my_client = MongoClient( self.DATABASE_HOST )
                #self.my_client.test.authenticate( self.DATABASE_USERNAME , self.DATABASE_PASSWORD )
            #dblist = my_client.list_database_names()
            self.my_db = self.my_client[self.DATABASE_NAME]
            if not collection_name in self.my_db.list_collection_names():
                # Add collection if it doesn't already exist
                # Not actually sure if needed, ngl
                # Collection will not actually be added until documents are added to set
                print("[+] Creating collection : {}!".format(collection_name))
                #print(self.my_db.list_collection_names())
                self.my_collection = self.my_db[collection_name]
            else:
                print("[+] Using existing collection : {}!".format(collection_name))
                self.my_collection = self.my_db[collection_name]

            print("[+] Database connected!")
        except Exception as e:
            print("[+] Database connection error!")
            raise e

    def get_client(self):
        return self.my_client

    def find_all(self, selector):
        return self.my_collection.find(selector)
 
    def find(self, selector):
        return self.my_collection.find_one(selector)
 
    def create(self, set):
        return self.my_collection.insert_one(set)

    def update(self, selector, set):
        return self.my_collection.replace_one(selector, set).modified_count
 
    def delete(self, selector):
        return self.my_collection.delete_one(selector).deleted_count

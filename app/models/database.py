from pymongo import MongoClient, ASCENDING
import os
from flask import current_app

class Database:
    def __init__(self):
        self.client = None
        self.db = None
        self.links = None
        self.users = None

    def init_app(self, app):
        uri = app.config['MONGODB_URI']
        db_name = app.config['MONGODB_DB_NAME']
        
        try:
            self.client = MongoClient(uri)
            self.db = self.client[db_name]
            self.links = self.db['links']
            self.users = self.db['users']
            
            # Create indexes
            self.links.create_index([("encrypted_token", ASCENDING)], unique=True)
            self.links.create_index([("username", ASCENDING)])
            self.links.create_index([("status", ASCENDING)])
            self.links.create_index([("created_at", ASCENDING)])
            
            self.users.create_index([("username", ASCENDING)], unique=True)
            self.users.create_index([("api_key", ASCENDING)], unique=True)
            
            print(f"SUCCESS: MongoDB connected successfully to {db_name}")
        except Exception as e:
            print(f"ERROR: MongoDB connection failed: {e}")
            raise

db = Database()

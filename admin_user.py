from pymongo import MongoClient
from pymongo.server_api import ServerApi
from datetime import datetime
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Establish MongoDB connection
uri = os.environ.get('MONGODB_URI')
client = MongoClient(uri, server_api=ServerApi('1'))
db = client["shelf_life_studies"]

# Insert admin user
db.users.insert_one({
    "username": "admin",
    "password_hash": generate_password_hash("admin123"),
    "role": "admin",
    "created_at": datetime.utcnow()
})
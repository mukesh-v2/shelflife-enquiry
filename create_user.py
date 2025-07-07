# create_user.py

import os
import getpass
from datetime import datetime
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

def main():
    # 1) Load environment variables from a .env file (if present)
    load_dotenv()  # expects a file named ".env" with MONGODB_URI, if you use one

    # 2) Read the MongoDB URI from environment (or replace with your URI directly)
    mongo_uri = os.environ.get("MONGODB_URI", None)
    if not mongo_uri:
        print("❌  Error: MONGODB_URI is not set. Please define it in your environment or .env file.")
        print("   Example .env line: MONGODB_URI=mongodb+srv://<user>:<pass>@cluster0.nv8kq.mongodb.net/shelf_life_studies?retryWrites=true&w=majority")
        return

    # 3) Connect to MongoDB
    try:
        client = MongoClient(mongo_uri)
        db = client.shelf_life_studies
        users_coll = db.users
    except Exception as e:
        print(f"❌  Could not connect to MongoDB: {e}")
        return

    # 4) Prompt for new user details
    print("=== Create a New User ===")
    username = input("Username: ").strip()
    if not username:
        print("❌  Username cannot be empty.")
        return

    # 5) Check if username already exists
    if users_coll.count_documents({"username": username}) > 0:
        print(f"⚠️   A user with username '{username}' already exists. Aborting.")
        return

    # 6) Prompt for password (hidden input)
    ##password = getpass.getpass("Password: ")
    password=input("Password ")
    if not password:
        print("❌  Password cannot be empty.")
        return

    # 7) Prompt for role (e.g. "admin" or "user")
    role = input("Role (e.g. admin or user): ").strip() or "user"

    # 8) Hash the password
   
    pw_hash = generate_password_hash(password)

    # 9) Insert into the "users" collection
    new_user = {
        "username": username,
        "password_hash": pw_hash,
        "role": role,
        "created_at": datetime.utcnow()
    }

    try:
        result = users_coll.insert_one(new_user)
        print(f"✅  New user '{username}' created with _id = {result.inserted_id}.")
    except Exception as e:
        print(f"❌  Failed to insert new user: {e}")

if __name__ == "__main__":
    main()

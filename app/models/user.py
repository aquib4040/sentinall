from .database import db
from datetime import datetime
from werkzeug.security import generate_password_hash

def create_user(user_data):
    try:
        result = db.users.insert_one(user_data)
        return str(result.inserted_id)
    except Exception as e:
        print(f"❌ Error creating user: {e}")
        raise

def get_user_by_username(username):
    try:
        return db.users.find_one({'username': username})
    except Exception as e:
        print(f"ERROR: Error fetching user: {e}")
        return None

def get_all_users():
    try:
        return list(db.users.find({}))
    except Exception as e:
        print(f"❌ Error fetching all users: {e}")
        return []

def update_user_settings(username, updates):
    try:
        result = db.users.update_one(
            {'username': username},
            {'$set': updates}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"❌ Error updating user settings: {e}")
        return False

def toggle_user_status(username, target_status):
    try:
        result = db.users.update_one(
            {'username': username},
            {'$set': {'status': target_status}}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"❌ Error toggling user status: {e}")
        return False

def delete_user(username):
    try:
        # Delete user and their links
        db.users.delete_one({'username': username})
        db.links.delete_many({'username': username})
        return True
    except Exception as e:
        print(f"❌ Error deleting user: {e}")
        return False

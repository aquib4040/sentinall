from .database import db
from datetime import datetime, timedelta

def create_link(link_data):
    try:
        result = db.links.insert_one(link_data)
        return str(result.inserted_id)
    except Exception as e:
        print(f"❌ Error creating link: {e}")
        raise

def get_link_by_token(encrypted_token):
    try:
        return db.links.find_one({'encrypted_token': encrypted_token})
    except Exception as e:
        print(f"❌ Error fetching link: {e}")
        return None

def get_link_by_verify_token(verify_token):
    try:
        return db.links.find_one({'verify_token': verify_token})
    except Exception as e:
        print(f"❌ Error fetching link by verify token: {e}")
        return None

def update_link_fingerprint(encrypted_token, updates):
    try:
        inc_data = updates.pop('$inc', None)
        update_query = {'$set': updates}
        if inc_data:
            update_query['$inc'] = inc_data
            
        result = db.links.update_one(
            {'encrypted_token': encrypted_token},
            update_query
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"❌ Error updating link fingerprint: {e}")
        return False

def mark_link_bypassed(encrypted_token, reason, message):
    try:
        db.links.update_one(
            {'encrypted_token': encrypted_token},
            {
                '$set': {
                    'is_bypassed': True,
                    'status': 'bypassed',
                    'bypassed_at': datetime.utcnow(),
                    'bypass_reason': reason,
                    'bypass_message': message
                }
            }
        )
        return True
    except Exception as e:
        print(f"❌ Error marking link as bypassed: {e}")
        return False

def mark_link_used(encrypted_token):
    try:
        db.links.update_one(
            {'encrypted_token': encrypted_token},
            {
                '$set': {
                    'captcha_verified': True,
                    'status': 'used',
                    'used_at': datetime.utcnow()
                }
            }
        )
        return True
    except Exception as e:
        print(f"❌ Error marking link as used: {e}")
        return False

def get_links_by_username(username, limit=50):
    try:
        return list(db.links.find({'username': username})
                    .sort('created_at', -1)
                    .limit(limit))
    except Exception as e:
        print(f"❌ Error fetching user links: {e}")
        return []

def auto_disable_old_links(username, hours):
    if hours <= 0: return 0
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    result = db.links.update_many(
        {
            'username': username,
            'status': 'active',
            'is_disabled': False,
            'created_at': {'$lt': cutoff}
        },
        {
            '$set': {
                'is_disabled': True,
                'disabled_at': datetime.utcnow()
            }
        }
    )
    return result.modified_count

def delete_disabled_links(username):
    result = db.links.delete_many({
        'username': username,
        'is_disabled': True
    })
    return result.deleted_count

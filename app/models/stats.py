from .database import db
from .user import get_user_by_username
from datetime import datetime

def get_user_stats(username):
    try:
        total_links = db.links.count_documents({'username': username})
        active_links = db.links.count_documents({
            'username': username,
            'status': 'active',
            'is_disabled': False
        })
        used_links = db.links.count_documents({
            'username': username,
            'status': 'used'
        })
        bypassed_links = db.links.count_documents({
            'username': username,
            'is_bypassed': True
        })
        disabled_links = db.links.count_documents({
            'username': username,
            'is_disabled': True
        })
        
        return {
            'total_links': total_links,
            'active_links': active_links,
            'used_links': used_links,
            'bypassed_links': bypassed_links,
            'disabled_links': disabled_links
        }
    except Exception as e:
        print(f"❌ Error fetching user stats: {e}")
        return {}

def get_user_earnings(username):
    try:
        COMPLETION_BONUS = 0.01
        user_links = list(db.links.find({'username': username}))
        
        now = datetime.utcnow()
        today_start = datetime(now.year, now.month, now.day)
        month_start = datetime(now.year, now.month, 1)
        
        def calculate(links):
            completed = len([l for l in links if l['status'] == 'used'])
            return {
                'total_links': len(links),
                'completed': completed,
                'total_earnings': completed * COMPLETION_BONUS
            }
        
        return {
            'daily': calculate([l for l in user_links if l['created_at'] >= today_start]),
            'monthly': calculate([l for l in user_links if l['created_at'] >= month_start]),
            'lifetime': calculate(user_links)
        }
    except Exception as e:
        print(f"❌ Error calculating earnings: {e}")
        return {}

def get_database_stats():
    try:
        return {
            'total_users': db.users.count_documents({}),
            'active_users': db.users.count_documents({'status': 'active'}),
            'total_links': db.links.count_documents({}),
            'active_links': db.links.count_documents({'status': 'active', 'is_disabled': False}),
            'used_links': db.links.count_documents({'status': 'used'}),
            'bypassed_links': db.links.count_documents({'is_bypassed': True}),
            'disabled_links': db.links.count_documents({'is_disabled': True})
        }
    except Exception as e:
        print(f"❌ Error fetching database stats: {e}")
        return None

from flask import Blueprint, request, jsonify, session, current_app
from datetime import datetime, timedelta
import requests
from urllib.parse import quote
from ..models.link import create_link, auto_disable_old_links, delete_disabled_links
from ..models.user import get_user_by_username
from ..models.database import db
from ..utils.security import generate_encrypted_token
from ..utils.decorators import login_required

api_bp = Blueprint('api', __name__)

@api_bp.route('/api/create', methods=['GET', 'POST'])
def create_short_link():
    if request.method == 'POST':
        data = request.get_json() or {}
        api_key = data.get('api')
        url = data.get('url')
    else:
        api_key = request.args.get('api')
        url = request.args.get('url')
    
    user = db.users.find_one({'api_key': api_key, 'status': 'active'})
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid or missing API key'}), 401
    
    if not url:
        return jsonify({'status': 'error', 'message': 'URL parameter is required'}), 400
    
    try:
        username = user['username']
        user_settings = user.get('settings', {})
        
        auto_disable_old_links(username, user_settings.get('auto_disable_hours', 0))
        if user_settings.get('auto_delete_disabled', False):
            delete_disabled_links(username)
        
        encrypted_token = generate_encrypted_token()
        verify_token = generate_encrypted_token()
        
        app_url = request.url_root.rstrip('/')
        verify_url = f"{app_url}/verify/{verify_token}"
        encoded_url = quote(verify_url, safe='')
        
        shortener_domain = user['shortener_domain']
        shortener_api_token = user['shortener_api_token']
        api_url = f"https://{shortener_domain}/api?api={shortener_api_token}&url={encoded_url}"
        
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                short_url = data.get('shortenedUrl')
                
                link_data = {
                    'encrypted_token': encrypted_token,
                    'original_url': url,
                    'short_url': short_url,
                    'username': username,
                    'initial_fingerprint': None,
                    'final_fingerprint': None,
                    'initial_cookies': None,
                    'final_cookies': None,
                    'captcha_verified': False,
                    'is_bypassed': False,
                    'is_disabled': False,
                    'start_accessed': False,
                    'verify_token': verify_token,
                    'usage_count': 0,
                    'visit_count': 0,
                    'created_at': datetime.utcnow(),
                    'verification_start_time': None,
                    'verification_end_time': None,
                    'status': 'active'
                }
                
                create_link(link_data)
                start_url = f"{app_url}/start/{encrypted_token}"
                
                return jsonify({
                    'status': 'success',
                    'shortenedUrl': start_url,
                    'original_url': url
                })
            else:
                return jsonify({'status': 'error', 'message': data.get('message', 'Shortener API error')}), 400
        else:
            return jsonify({'status': 'error', 'message': 'Shortener API request failed'}), 500
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Link creation failed: {str(e)}'}), 500

@api_bp.route('/api', methods=['GET', 'POST'])
def api_alias():
    return create_short_link()

@api_bp.route('/api/analytics/summary')
@login_required
def get_analytics_summary():
    username = session['username']
    user_links = list(db.links.find({'username': username}))
    
    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    month_start = datetime(now.year, now.month, 1)
    
    def count_stats(links):
        return {
            'total_created': len(links),
            'total_completed': len([l for l in links if l['status'] == 'used']),
            'total_bypassed': len([l for l in links if l.get('is_bypassed')]),
            'total_active': len([l for l in links if l['status'] == 'active' and not l.get('is_disabled')])
        }
    
    return jsonify({
        'status': 'success',
        'daily': count_stats([l for l in user_links if l['created_at'] >= today_start]),
        'monthly': count_stats([l for l in user_links if l['created_at'] >= month_start]),
        'lifetime': count_stats(user_links)
    })

@api_bp.route('/api/analytics/monthly')
@login_required
def get_monthly_analytics():
    username = session['username']
    now = datetime.utcnow()
    monthly_data = []
    
    for i in range(12):
        month_date = now - timedelta(days=30*i)
        year, month = month_date.year, month_date.month
        start_date = datetime(year, month, 1)
        if month == 12:
            end_date = datetime(year + 1, 1, 1)
        else:
            end_date = datetime(year, month + 1, 1)
        
        month_links = list(db.links.find({
            'username': username,
            'created_at': {'$gte': start_date, '$lt': end_date}
        }))
        
        monthly_data.append({
            'month': start_date.strftime('%Y-%m'),
            'display': start_date.strftime('%B %Y'),
            'created': len(month_links),
            'completed': len([l for l in month_links if l['status'] == 'used']),
            'bypassed': len([l for l in month_links if l.get('is_bypassed')]),
            'active': len([l for l in month_links if l['status'] == 'active' and not l.get('is_disabled')])
        })
    
    return jsonify({'status': 'success', 'data': monthly_data})

@api_bp.route('/api/analytics/daily/<month>')
@login_required
def get_daily_analytics(month):
    username = session['username']
    try:
        year, month_num = map(int, month.split('-'))
        start_date = datetime(year, month_num, 1)
        if month_num == 12:
            end_date = datetime(year + 1, 1, 1)
        else:
            end_date = datetime(year, month_num + 1, 1)
        
        month_links = list(db.links.find({
            'username': username,
            'created_at': {'$gte': start_date, '$lt': end_date}
        }))
        
        daily_stats = []
        current = start_date
        while current < end_date:
            next_day = current + timedelta(days=1)
            day_links = [l for l in month_links if current <= l['created_at'] < next_day]
            daily_stats.append({
                'date': current.strftime('%d %b'),
                'created': len(day_links),
                'completed': len([l for l in day_links if l['status'] == 'used']),
                'bypassed': len([l for l in day_links if l.get('is_bypassed')]),
                'active': len([l for l in day_links if l['status'] == 'active' and not l.get('is_disabled')])
            })
            current = next_day
        
        return jsonify({'status': 'success', 'data': daily_stats})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

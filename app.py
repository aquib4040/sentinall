from flask import Flask, redirect, jsonify, request, render_template_string, session, url_for
from cryptography.fernet import Fernet
import requests
import os
from urllib.parse import quote, urlparse
import secrets
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from db import (
    links_collection, users_collection,
    get_link_by_token, create_link, update_link_fingerprint, 
    mark_link_bypassed, mark_link_used, create_user, 
    get_user_by_username, update_user_settings, get_user_stats,
    get_all_users, get_user_earnings, disable_user,
    auto_disable_old_links, delete_disabled_links, get_links_by_username
)
from collections import defaultdict
import hashlib
import json
import random

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

# Session Configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_NAME'] = 'urlshortener_session'

# Admin Configuration
OWNER_EMAIL = os.environ.get('OWNER_EMAIL')
OWNER_PASSWORD = os.environ.get('OWNER_PASSWORD')
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
cipher = Fernet(ENCRYPTION_KEY.encode())

# ==================== HELPER FUNCTIONS ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in') or 'user_id' not in session or 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def owner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('owner_logged_in'):
            return redirect(url_for('owner_login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_fingerprint():
    """Generate a browser fingerprint hash from request headers"""
    fingerprint_data = {
        'user_agent': request.headers.get('User-Agent', ''),
        'accept_language': request.headers.get('Accept-Language', ''),
        'accept_encoding': request.headers.get('Accept-Encoding', ''),
        'platform': request.headers.get('Sec-Ch-Ua-Platform', ''),
    }
    fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()

def get_cookie_data():
    """Extract cookie data from request"""
    return {
        'cookies': dict(request.cookies),
        'has_cookies': len(request.cookies) > 0
    }

def generate_encrypted_token():
    random_string = secrets.token_urlsafe(32)
    return cipher.encrypt(random_string.encode()).decode()

def is_allowed_browser():
    """Check if the browser is Chrome or Edge"""
    user_agent = request.headers.get('User-Agent', '').lower()
    # Check for Chrome (but not Edge, as Edge also contains 'chrome')
    is_chrome = 'chrome' in user_agent and 'edg' not in user_agent
    # Check for Edge (Chromium-based Edge contains 'edg')
    is_edge = 'edg' in user_agent
    return is_chrome or is_edge

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/')
def home():
    if session.get('owner_logged_in'):
        return redirect(url_for('owner_dashboard'))
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/api-docs')
@login_required
def api_docs():
    """API Documentation Page"""
    app_url = request.url_root.rstrip('/')
    user = get_user_by_username(session['username'])
    return render_template_string(API_DOCS_TEMPLATE, app_url=app_url, user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.form
            
            admin_pass = data.get('admin_password')
            if admin_pass != OWNER_PASSWORD:
                return render_template_string(REGISTER_TEMPLATE, 
                    error='Invalid admin password. Contact the owner for access.')
            
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            recaptcha_site_key = data.get('recaptcha_site_key', '').strip()
            recaptcha_secret_key = data.get('recaptcha_secret_key', '').strip()
            arolinks_api_token = data.get('arolinks_api_token', '').strip()
            shortener_domain = data.get('shortener_domain', '').strip()
            
            if not all([username, password, recaptcha_site_key, recaptcha_secret_key, arolinks_api_token, shortener_domain]):
                return render_template_string(REGISTER_TEMPLATE, 
                    error='All fields are required.')
            
            if get_user_by_username(username):
                return render_template_string(REGISTER_TEMPLATE, 
                    error='Username already exists.')
            
            user_data = {
                'username': username,
                'password': generate_password_hash(password),
                'api_key': secrets.token_urlsafe(32),
                'recaptcha_site_key': recaptcha_site_key,
                'recaptcha_secret_key': recaptcha_secret_key,
                'arolinks_api_token': arolinks_api_token,
                'shortener_domain': shortener_domain.replace('https://', '').replace('http://', ''),
                'created_at': datetime.utcnow(),
                'status': 'active',
                'settings': {
                    'verification_time_seconds': 0,  # User sets this
                    'auto_disable_hours': 0,  # User sets this
                    'check_fingerprint': True,
                    'check_cookies': True,
                    'auto_delete_disabled': False,  # User chooses
                    'disable_link_after_use': True,  # Disable link after successful verification
                    'recaptcha_on_start': False,  # Show reCAPTCHA on /start/ page
                    'recaptcha_on_verify': True,  # Show reCAPTCHA on /verify/ page
                    'enable_verification_time_check': True,  # Enable/disable verification time check
                    'enable_fingerprint_check': True,  # Enable/disable fingerprint check
                    'enable_cookie_check': True,  # Enable/disable cookie check
                    # NEW SETTINGS - Link Blocking
                    'block_after_first_visit': True,  # Block /start/ page after first visit
                    'block_after_bypass': True,  # Block entire link when bypass detected
                    'block_after_verify_complete': True,  # Block link after successful verification
                    # NEW SETTINGS - Visitor Tracking
                    'store_visitor_details': True,  # Store visitor IP, user-agent on first visit
                    'max_visits_allowed': 1,  # Max visits before blocking (0 = unlimited)
                    'require_same_ip': False,  # Require same IP on start and verify
                    'check_shortener_referer': True,  # Check if user came from shortener
                    'show_visit_count': True  # Track and display visit count
                }
            }
            
            create_user(user_data)
            return render_template_string(REGISTER_TEMPLATE, 
                success='Account created successfully! Please login.')
            
        except Exception as e:
            return render_template_string(REGISTER_TEMPLATE, 
                error=f'Registration failed: {str(e)}')
    
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        remember_me = request.form.get('remember_me') == 'yes'
        
        user = get_user_by_username(username)
        
        if user and check_password_hash(user['password'], password):
            if user.get('status') != 'active':
                return render_template_string(LOGIN_TEMPLATE, 
                    error='Your account has been disabled.')
            
            if remember_me:
                session.permanent = True
                app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
            else:
                session.permanent = False
            
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['logged_in'] = True
            session['remember_me'] = remember_me
            session.modified = True
            
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(LOGIN_TEMPLATE, 
                error='Invalid username or password.')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/owner-login', methods=['GET', 'POST'])
def owner_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if email == OWNER_EMAIL and password == OWNER_PASSWORD:
            session['owner_logged_in'] = True
            session['owner_email'] = email
            session.modified = True
            return redirect(url_for('owner_dashboard'))
        else:
            return render_template_string(OWNER_LOGIN_TEMPLATE, 
                error='Invalid email or password.')
    
    return render_template_string(OWNER_LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/owner-logout')
def owner_logout():
    session.clear()
    return redirect(url_for('owner_login'))

# ==================== OWNER DASHBOARD ROUTES ====================

@app.route('/owner-dashboard')
@owner_required
def owner_dashboard():
    try:
        all_users = get_all_users()
        total_stats = {
            'total_users': len(all_users),
            'active_users': len([u for u in all_users if u.get('status') == 'active']),
            'total_links': links_collection.count_documents({}),
            'total_earnings': 0
        }
        
        for user in all_users:
            earnings = get_user_earnings(user['username'])
            total_stats['total_earnings'] += earnings.get('lifetime', {}).get('total_earnings', 0)
        
        return render_template_string(OWNER_DASHBOARD_TEMPLATE,
            users=all_users,
            total_stats=total_stats)
    except Exception as e:
        return render_template_string(OWNER_DASHBOARD_TEMPLATE,
            error=f'Error loading dashboard: {str(e)}',
            users=[],
            total_stats={'total_users': 0, 'active_users': 0, 'total_links': 0, 'total_earnings': 0})

@app.route('/owner/user/<username>')
@owner_required
def owner_user_details(username):
    try:
        user = get_user_by_username(username)
        if not user:
            return render_template_string(ERROR_TEMPLATE,
                error_title='User Not Found',
                error_message='This user does not exist.')
        
        user_links = get_links_by_username(username, limit=100)
        earnings = get_user_earnings(username)
        stats = get_user_stats(username)
        
        return render_template_string(OWNER_USER_TEMPLATE,
            user=user,
            stats=stats,
            earnings=earnings,
            user_links=user_links,
            app_url=request.url_root.rstrip('/'))
    except Exception as e:
        return render_template_string(ERROR_TEMPLATE,
            error_title='Error',
            error_message=f'Error loading user details: {str(e)}')

@app.route('/owner/user/<username>/disable', methods=['POST'])
@owner_required
def owner_disable_user(username):
    try:
        disable_user(username)
        return jsonify({'status': 'success', 'message': f'User {username} has been disabled'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/owner/user/<username>/delete', methods=['POST'])
@owner_required
def owner_delete_user(username):
    try:
        users_collection.delete_one({'username': username})
        links_collection.delete_many({'username': username})
        return jsonify({'status': 'success', 'message': f'User {username} and all associated links have been deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# ==================== DASHBOARD ROUTES ====================

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_user_by_username(session['username'])
    stats = get_user_stats(session['username'])
    
    # Auto-process based on user settings
    auto_disable_old_links(session['username'])
    delete_disabled_links(session['username'])
    
    return render_template_string(DASHBOARD_TEMPLATE, 
        user=user, 
        stats=stats)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = get_user_by_username(session['username'])
    
    if request.method == 'POST':
        try:
            updates = {
                'recaptcha_site_key': request.form.get('recaptcha_site_key', '').strip(),
                'recaptcha_secret_key': request.form.get('recaptcha_secret_key', '').strip(),
                'arolinks_api_token': request.form.get('arolinks_api_token', '').strip(),
                'shortener_domain': request.form.get('shortener_domain', '').strip().replace('https://', '').replace('http://', ''),
                'settings': {
                    'verification_time_seconds': int(request.form.get('verification_time_seconds', 0) or 0),
                    'auto_disable_hours': int(request.form.get('auto_disable_hours', 0) or 0),
                    'check_fingerprint': request.form.get('check_fingerprint') == 'on',
                    'check_cookies': request.form.get('check_cookies') == 'on',
                    'auto_delete_disabled': request.form.get('auto_delete_disabled') == 'on',
                    'disable_link_after_use': request.form.get('disable_link_after_use') == 'on',
                    'recaptcha_on_start': request.form.get('recaptcha_on_start') == 'on',
                    'recaptcha_on_verify': request.form.get('recaptcha_on_verify') == 'on',
                    'enable_verification_time_check': request.form.get('enable_verification_time_check') == 'on',
                    'enable_fingerprint_check': request.form.get('enable_fingerprint_check') == 'on',
                    'enable_cookie_check': request.form.get('enable_cookie_check') == 'on',
                    # NEW SETTINGS - Link Blocking
                    'block_after_first_visit': request.form.get('block_after_first_visit') == 'on',
                    'block_after_bypass': request.form.get('block_after_bypass') == 'on',
                    'block_after_verify_complete': request.form.get('block_after_verify_complete') == 'on',
                    # NEW SETTINGS - Visitor Tracking
                    'store_visitor_details': request.form.get('store_visitor_details') == 'on',
                    'max_visits_allowed': int(request.form.get('max_visits_allowed', 1) or 1),
                    'require_same_ip': request.form.get('require_same_ip') == 'on',
                    'check_shortener_referer': request.form.get('check_shortener_referer') == 'on',
                    'show_visit_count': request.form.get('show_visit_count') == 'on'
                }
            }
            
            new_password = request.form.get('new_password', '').strip()
            if new_password:
                updates['password'] = generate_password_hash(new_password)
            
            update_user_settings(session['username'], updates)
            
            return render_template_string(SETTINGS_TEMPLATE, 
                user=get_user_by_username(session['username']),
                success='Settings updated successfully!')
            
        except Exception as e:
            return render_template_string(SETTINGS_TEMPLATE, 
                user=user,
                error=f'Update failed: {str(e)}')
    
    return render_template_string(SETTINGS_TEMPLATE, user=user)

@app.route('/analytics')
@login_required
def analytics_page():
    user = get_user_by_username(session['username'])
    current_month = datetime.utcnow().strftime('%Y-%m')
    
    return render_template_string(ANALYTICS_TEMPLATE,
        user=user,
        current_month=current_month,
        app_url=request.url_root.rstrip('/'))

# ==================== API ROUTES ====================

@app.route('/api/create', methods=['GET', 'POST'])
def create_short_link():
    if request.method == 'POST':
        data = request.get_json()
        api_key = data.get('api')
        url = data.get('url')
    else:
        api_key = request.args.get('api')
        url = request.args.get('url')
    
    user = users_collection.find_one({'api_key': api_key, 'status': 'active'})
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid or missing API key'}), 401
    
    if not url:
        return jsonify({'status': 'error', 'message': 'URL parameter is required'}), 400
    
    try:
        # Auto-process old links
        auto_disable_old_links(user['username'])
        delete_disabled_links(user['username'])
        
        # Generate BOTH tokens upfront
        encrypted_token = generate_encrypted_token()
        verify_token = generate_encrypted_token()  # Unique verify token
        
        app_url = request.url_root.rstrip('/')
        
        # Use verify_token in the final URL (this gets embedded in arolinks)
        verify_url = f"{app_url}/verify/{verify_token}"
        encoded_url = quote(verify_url, safe='')
        
        shortener_domain = user['shortener_domain']
        arolinks_api_token = user['arolinks_api_token']
        api_url = f"https://{shortener_domain}/api?api={arolinks_api_token}&url={encoded_url}"
        
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status') == 'success':
                short_url = data.get('shortenedUrl')
                
                link_data = {
                    'encrypted_token': encrypted_token,
                    'original_url': url,
                    'short_url': short_url,
                    'username': user['username'],
                    'initial_fingerprint': None,
                    'final_fingerprint': None,
                    'initial_cookies': None,
                    'final_cookies': None,
                    'captcha_verified': False,
                    'is_bypassed': False,
                    'is_disabled': False,
                    'start_accessed': False,  # Track if /start was accessed
                    'verify_token': verify_token,  # Pre-generated verify token
                    'usage_count': 0,  # Track number of times link has been used
                    'click_count': 0,
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
                error_message = data.get('message', 'Unknown error')
                return jsonify({'status': 'error', 'message': f'Shortener API error: {error_message}'}), 400
        else:
            return jsonify({'status': 'error', 'message': 'Shortener API request failed'}), 500
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Link creation failed: {str(e)}'}), 500

@app.route('/api', methods=['GET', 'POST'])
def api_alias():
    return create_short_link()

@app.route('/api/analytics/summary', methods=['GET'])
@login_required
def get_analytics_summary():
    username = session['username']
    user_links = list(links_collection.find({'username': username}))
    
    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)
    month_start = datetime(now.year, now.month, 1)
    
    def filter_links(links, start_time):
        return [l for l in links if l['created_at'] >= start_time]
    
    def count_stats(links):
        return {
            'total_created': len(links),
            'total_completed': len([l for l in links if l['status'] == 'used']),
            'total_bypassed': len([l for l in links if l['is_bypassed']]),
            'total_active': len([l for l in links if l['status'] == 'active' and not l['is_disabled']])
        }
    
    return jsonify({
        'status': 'success',
        'daily': count_stats(filter_links(user_links, today_start)),
        'monthly': count_stats(filter_links(user_links, month_start)),
        'lifetime': count_stats(user_links)
    })

@app.route('/api/analytics/monthly', methods=['GET'])
@login_required
def get_monthly_analytics():
    username = session['username']
    
    # Generate last 12 months
    months = []
    now = datetime.utcnow()
    for i in range(12):
        month_date = now - timedelta(days=30*i)
        month_str = month_date.strftime('%Y-%m')
        months.append({
            'month': month_str,
            'display': month_date.strftime('%B %Y')
        })
    
    # Get stats for each month
    monthly_data = []
    for month_info in months:
        year, month = map(int, month_info['month'].split('-'))
        start_date = datetime(year, month, 1)
        if month == 12:
            end_date = datetime(year + 1, 1, 1)
        else:
            end_date = datetime(year, month + 1, 1)
        
        month_links = list(links_collection.find({
            'username': username,
            'created_at': {'$gte': start_date, '$lt': end_date}
        }))
        
        monthly_data.append({
            'month': month_info['month'],
            'display': month_info['display'],
            'created': len(month_links),
            'completed': len([l for l in month_links if l['status'] == 'used']),
            'bypassed': len([l for l in month_links if l['is_bypassed']]),
            'active': len([l for l in month_links if l['status'] == 'active' and not l['is_disabled']])
        })
    
    return jsonify({
        'status': 'success',
        'data': monthly_data
    })

@app.route('/api/analytics/daily/<month>', methods=['GET'])
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
        
        # Get all links for the month
        month_links = list(links_collection.find({
            'username': username,
            'created_at': {'$gte': start_date, '$lt': end_date}
        }))
        
        # Group by day
        daily_stats = {}
        current = start_date
        while current < end_date:
            day_str = current.strftime('%Y-%m-%d')
            next_day = current + timedelta(days=1)
            
            day_links = [l for l in month_links if current <= l['created_at'] < next_day]
            
            daily_stats[day_str] = {
                'date': current.strftime('%d %b'),
                'created': len(day_links),
                'completed': len([l for l in day_links if l['status'] == 'used']),
                'bypassed': len([l for l in day_links if l['is_bypassed']]),
                'active': len([l for l in day_links if l['status'] == 'active' and not l['is_disabled']])
            }
            
            current = next_day
        
        return jsonify({
            'status': 'success',
            'data': list(daily_stats.values())
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ==================== LINK ROUTES ====================

@app.route('/start/<encrypted_token>')
def start_redirect(encrypted_token):
    try:
        # 🔒 BROWSER RESTRICTION: Only allow Chrome and Edge
        if not is_allowed_browser():
            return render_template_string(BROWSER_RESTRICTION_TEMPLATE)
        
        fingerprint = generate_fingerprint()
        cookie_data = get_cookie_data()
        
        # Get visitor details
        visitor_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if visitor_ip and ',' in visitor_ip:
            visitor_ip = visitor_ip.split(',')[0].strip()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        link = get_link_by_token(encrypted_token)
        
        if not link:
            return render_template_string(ERROR_TEMPLATE, 
                error_title="Link Not Found",
                error_message='This link does not exist or has expired.')
        
        if link.get('is_disabled', False):
            return render_template_string(ERROR_TEMPLATE,
                error_title="Link Disabled",
                error_message='This link has been disabled.')
        
        if link.get('is_bypassed', False):
            # Show roast title and stored message
            roast_titles = ['Nice Try Diddy! 🤡', 'Caught Lacking! 📸', 'You Thought! 💀', 'Not Today Fam! 🚫', 'L + Ratio 😂']
            stored_message = link.get('bypass_message', 'This link has been blocked. Better luck next time!')
            return render_template_string(ERROR_TEMPLATE,
                error_title=random.choice(roast_titles),
                error_message=stored_message)
        
        if link.get('status') == 'used':
            return render_template_string(ERROR_TEMPLATE,
                error_title="Link Already Used",
                error_message='This link has already been used.')
        
        
        user = get_user_by_username(link['username'])
        user_settings = user.get('settings', {})
        
        # 🔒 NEW: Check max visits allowed
        max_visits = user_settings.get('max_visits_allowed', 1)
        current_visits = link.get('visit_count', 0)
        
        if max_visits > 0 and current_visits >= max_visits:
            return render_template_string(ERROR_TEMPLATE,
                error_title="Link Limit Reached",
                error_message=f'This link has reached its maximum visits limit ({max_visits}).')
        
        # 🔒 SECURITY: Check if /start was already accessed (block_after_first_visit)
        block_after_first_visit = user_settings.get('block_after_first_visit', True)
        
        if block_after_first_visit and link.get('initial_fingerprint') is not None:
            # Link was already accessed - block repeated /start attempts
            return render_template_string(ERROR_TEMPLATE,
                error_title="Invalid Access",
                error_message='This link has already been initialized. Please use the verification link OR Regenerate The Link. Any Problem Contact The Respective Owner.')
        
        
        # Check if auto-disable is set
        if user_settings.get('auto_disable_hours', 0) > 0:
            hours = user_settings['auto_disable_hours']
            expiry_time = link['created_at'] + timedelta(hours=hours)
            if datetime.utcnow() > expiry_time:
                return render_template_string(ERROR_TEMPLATE,
                    error_title="Link Expired",
                    error_message=f'This link expired after {hours} hours.')
        
        # Check if reCAPTCHA is enabled on start page
        recaptcha_on_start = user_settings.get('recaptcha_on_start', False)
        
        if recaptcha_on_start:
            # Show reCAPTCHA page before redirecting
            return render_template_string(START_CAPTCHA_TEMPLATE,
                site_key=user['recaptcha_site_key'],
                encrypted_token=encrypted_token)
        
        # No reCAPTCHA required, proceed with redirect
        # Record initial fingerprint and cookies (marks link as "started")
        update_link_fingerprint(
            encrypted_token, 
            initial_fingerprint=fingerprint,
            initial_cookies=cookie_data
        )
        
        # 🔒 NEW: Store visitor details if enabled
        update_data = {
            'verification_start_time': datetime.utcnow(),
            'start_accessed': True  # Flag to prevent re-access and verify bypass
        }
        
        if user_settings.get('store_visitor_details', True):
            update_data['visitor_ip'] = visitor_ip
            update_data['visitor_user_agent'] = user_agent
            update_data['first_visit_time'] = datetime.utcnow()
        
        # 🔒 NEW: Increment visit count if tracking enabled
        if user_settings.get('show_visit_count', True):
            links_collection.update_one(
                {'encrypted_token': encrypted_token},
                {
                    '$set': update_data,
                    '$inc': {'visit_count': 1}
                }
            )
        else:
            links_collection.update_one(
                {'encrypted_token': encrypted_token},
                {'$set': update_data}
            )
        
        short_url = link['short_url']
        return redirect(short_url, code=302)
        
    except Exception as e:
        return render_template_string(ERROR_TEMPLATE,
            error_title="Error",
            error_message=f"An error occurred: {str(e)}")


@app.route('/verify/<verify_token>')
def verify_page(verify_token):
    try:
        # 🔒 BROWSER RESTRICTION: Only allow Chrome and Edge
        if not is_allowed_browser():
            return render_template_string(BROWSER_RESTRICTION_TEMPLATE)
        
        fingerprint = generate_fingerprint()
        cookie_data = get_cookie_data()
        
        # Get current visitor IP
        current_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if current_ip and ',' in current_ip:
            current_ip = current_ip.split(',')[0].strip()
        
        # Get referer header
        referer = request.headers.get('Referer', '')
        
        # Find link by verify_token instead of encrypted_token
        link = links_collection.find_one({'verify_token': verify_token})
        
        if not link:
            return render_template_string(ERROR_TEMPLATE,
                error_title="Link Not Found",
                error_message='This link does not exist or has expired.')
        
        # 🔒 CRITICAL SECURITY CHECK: Ensure /start/ was accessed first
        if not link.get('start_accessed', False):
            return render_template_string(ERROR_TEMPLATE,
                error_title="Nice Try Diddy! 🤡",
                error_message='Caught you red-handed trying to sneak in! You thought you were slick? LMAO. Go back and do it the right way, genius.')
        
        # 🔒 CRITICAL: Verify that the verify_token matches
        if link.get('verify_token') != verify_token:
            return render_template_string(ERROR_TEMPLATE,
                error_title="Invalid Token",
                error_message='Invalid verification token. Please use the correct link.')
        
        if link.get('is_bypassed', False):
            # Show roast title and stored message
            roast_titles = ['Nice Try Diddy! 🤡', 'Caught Lacking! 📸', 'You Thought! 💀', 'Not Today Fam! 🚫', 'L + Ratio 😂']
            stored_message = link.get('bypass_message', 'This link has been blocked. Better luck next time!')
            return render_template_string(ERROR_TEMPLATE,
                error_title=random.choice(roast_titles),
                error_message=stored_message)
        
        if link.get('status') == 'used':
            return render_template_string(ERROR_TEMPLATE,
                error_title="Link Already Used",
                error_message='This link has already been used.')
        
        user = get_user_by_username(link['username'])
        user_settings = user.get('settings', {})
        encrypted_token = link['encrypted_token']
        
        # 🔒 NEW: Check if same IP is required
        if user_settings.get('require_same_ip', False):
            stored_ip = link.get('visitor_ip', '')
            if stored_ip and current_ip != stored_ip:
                # IP changed - mark as bypassed
                if user_settings.get('block_after_bypass', True):
                    mark_link_bypassed(encrypted_token, 'ip_change', 'Switching IPs like you switching personalities? We see you fam. Your little VPN tricks dont work here. Stay mad.')
                return render_template_string(ERROR_TEMPLATE,
                    error_title="VPN Andy Detected! 🕵️",
                    error_message='Switching IPs like you switching personalities? We see you fam. Your little VPN tricks dont work here. Stay mad.')
        
        # 🔒 NEW: Check shortener referer using user's configured domain
        if user_settings.get('check_shortener_referer', True):
            # Get shortener domain from user config (e.g., "api.gplinks.com")
            configured_domain = user.get('shortener_domain', '').lower()
            referer_domain = urlparse(referer).netloc.lower() if referer else ''
            
            if configured_domain and referer:
                # Extract core domain name (e.g., "gplinks" from "api.gplinks.com")
                # Split by dots and get the main part (usually second-to-last)
                domain_parts = configured_domain.replace('api.', '').replace('www.', '').split('.')
                core_domain = domain_parts[0] if domain_parts else configured_domain
                
                # Check if referer contains the core domain (e.g., "gplinks")
                if core_domain and referer_domain:
                    if core_domain not in referer_domain:
                        # User didn't come from the shortener - block!
                        if user_settings.get('block_after_bypass', True):
                            mark_link_bypassed(encrypted_token, 'referer_bypass', 'LMAOOO you really thought you could skip the ads? Bro really said "I am the main character". Nah fam, go watch the ads like everyone else. We got bills to pay.')
                        return render_template_string(ERROR_TEMPLATE,
                            error_title="Caught Lacking! 📸",
                            error_message='LMAOOO you really thought you could skip the ads? Bro really said "I am the main character". Nah fam, go watch the ads like everyone else. We got bills to pay.')
        
        # Record final fingerprint and cookies
        update_link_fingerprint(
            encrypted_token, 
            final_fingerprint=fingerprint,
            final_cookies=cookie_data
        )
        
        # Store verify page IP for comparison
        links_collection.update_one(
            {'encrypted_token': encrypted_token},
            {'$set': {'verify_ip': current_ip, 'verify_referer': referer}}
        )
        
        return render_template_string(CAPTCHA_TEMPLATE,
            site_key=user['recaptcha_site_key'],
            encrypted_token=encrypted_token,
            verify_token=verify_token)
        
    except Exception as e:
        return render_template_string(ERROR_TEMPLATE,
            error_title="Error",
            error_message=f"An error occurred: {str(e)}")


@app.route('/verify-start-captcha', methods=['POST'])
def verify_start_captcha():
    """Verify reCAPTCHA on start page and redirect to short URL"""
    try:
        data = request.get_json()
        encrypted_token = data.get('token')
        recaptcha_response = data.get('recaptcha')
        
        if not encrypted_token or not recaptcha_response:
            return jsonify({'status': 'error', 'message': 'Missing required parameters'}), 400
        
        link = get_link_by_token(encrypted_token)
        
        if not link:
            return jsonify({'status': 'error', 'message': 'Link not found'}), 404
        
        user = get_user_by_username(link['username'])
        
        # Verify reCAPTCHA
        try:
            payload = {
                'secret': user['recaptcha_secret_key'],
                'response': recaptcha_response
            }
            response = requests.post('https://www.google.com/recaptcha/api/siteverify', 
                                   data=payload, timeout=10)
            result = response.json()
            if not result.get('success', False):
                return jsonify({'status': 'error', 'message': 'reCAPTCHA verification failed'}), 400
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'reCAPTCHA error: {str(e)}'}), 400
        
        # reCAPTCHA verified, now record fingerprint and set start_accessed
        fingerprint = generate_fingerprint()
        cookie_data = get_cookie_data()
        
        # Record initial fingerprint and cookies
        update_link_fingerprint(
            encrypted_token, 
            initial_fingerprint=fingerprint,
            initial_cookies=cookie_data
        )
        
        # Set start_accessed flag
        links_collection.update_one(
            {'encrypted_token': encrypted_token},
            {'$set': {
                'verification_start_time': datetime.utcnow(),
                'start_accessed': True
            }}
        )
        
        # Return the short URL to redirect to
        return jsonify({
            'status': 'success',
            'redirect_url': link['short_url']
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Verification failed: {str(e)}'
        }), 500


@app.route('/verify-captcha', methods=['POST'])
def verify_captcha():
    try:
        data = request.get_json()
        encrypted_token = data.get('token')
        recaptcha_response = data.get('recaptcha')
        
        if not encrypted_token:
            return jsonify({'status': 'error', 'message': 'Missing required parameters'}), 400
        
        link = get_link_by_token(encrypted_token)
        
        if not link:
            return jsonify({'status': 'error', 'message': 'Link not found'}), 404
        
        user = get_user_by_username(link['username'])
        
        # Verify reCAPTCHA only if enabled on verify page
        if user.get('settings', {}).get('recaptcha_on_verify', True):
            if not recaptcha_response:
                return jsonify({'status': 'error', 'message': 'Missing reCAPTCHA response'}), 400
            
            try:
                payload = {
                    'secret': user['recaptcha_secret_key'],
                    'response': recaptcha_response
                }
                response = requests.post('https://www.google.com/recaptcha/api/siteverify', 
                                       data=payload, timeout=10)
                result = response.json()
                if not result.get('success', False):
                    return jsonify({'status': 'error', 'message': 'reCAPTCHA verification failed'}), 400
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'reCAPTCHA error: {str(e)}'}), 400
        
        # Check verification time only if enabled
        if user.get('settings', {}).get('enable_verification_time_check', True):
            verification_time = user.get('settings', {}).get('verification_time_seconds', 0)
            if verification_time > 0:
                start_time = link.get('verification_start_time')
                end_time = datetime.utcnow()
                
                if start_time:
                    elapsed = (end_time - start_time).total_seconds()
                    if elapsed < verification_time:
                        mark_link_bypassed(encrypted_token, 'speedrun', 'Speedrunning are we? Bro completed in record time! Too bad we caught your bypass attempt. GGs only.')
                        return jsonify({
                            'status': 'error',
                            'message': 'Speedrunning are we? 🏃 Bro completed in record time! Too bad we caught your bypass attempt. GGs only.',
                            'bypass_detected': True
                        }), 403
        
        # Check fingerprint only if enabled
        if user.get('settings', {}).get('enable_fingerprint_check', True):
            if user.get('settings', {}).get('check_fingerprint', True):
                initial_fp = link.get('initial_fingerprint')
                final_fp = link.get('final_fingerprint')
                
                if initial_fp and final_fp and initial_fp != final_fp:
                    mark_link_bypassed(encrypted_token, 'device_swap', 'Device swap detected! You started on one device and finished on another? Thats wild. Nice try tho, Diddy would be proud.')
                    return jsonify({
                        'status': 'error',
                        'message': 'Device swap detected! 📱💻 You started on one device and finished on another? Thats wild. Nice try tho, Diddy would be proud.',
                        'bypass_detected': True
                    }), 403
        
        # Check cookies only if enabled
        if user.get('settings', {}).get('enable_cookie_check', True):
            if user.get('settings', {}).get('check_cookies', True):
                initial_cookies = link.get('initial_cookies', {})
                final_cookies = link.get('final_cookies', {})
                
                if initial_cookies.get('has_cookies') != final_cookies.get('has_cookies'):
                    mark_link_bypassed(encrypted_token, 'cookie_mismatch', 'Cookie monster alert! Your cookies dont match. Did you clear them hoping wed forget? We never forget. NEVER.')
                    return jsonify({
                        'status': 'error',
                        'message': 'Cookie monster alert! 🍪 Your cookies dont match. Did you clear them hoping wed forget? We never forget. NEVER.',
                        'bypass_detected': True
                    }), 403
        
        # Record final time
        links_collection.update_one(
            {'encrypted_token': encrypted_token},
            {'$set': {'verification_end_time': datetime.utcnow()}}
        )
        
        user_settings = user.get('settings', {})
        
        # 🔒 NEW: Block link after verification complete (if enabled)
        if user_settings.get('block_after_verify_complete', True):
            mark_link_used(encrypted_token)
        elif user_settings.get('disable_link_after_use', True):
            # Legacy setting - also marks as used
            mark_link_used(encrypted_token)
        else:
            # Just increment usage count without disabling
            links_collection.update_one(
                {'encrypted_token': encrypted_token},
                {'$inc': {'usage_count': 1}}
            )
        
        return jsonify({
            'status': 'success',
            'redirect_url': link['original_url']
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Verification failed: {str(e)}'
        }), 500

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'}), 200
# ==================== TEMPLATES ====================

REGISTER_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - URL Shortener</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 500px;
            width: 100%;
        }
        h1 { color: #333; margin-bottom: 10px; text-align: center; font-size: 32px; }
        .subtitle { text-align: center; color: #666; margin-bottom: 30px; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; color: #333; margin-bottom: 8px; font-weight: 600; font-size: 14px; }
        input { width: 100%; padding: 12px 15px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 14px; transition: border-color 0.3s; }
        input:focus { outline: none; border-color: #667eea; }
        .helper-text { font-size: 12px; color: #999; margin-top: 5px; }
        button {
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4); }
        .alert { padding: 15px; border-radius: 10px; margin-bottom: 20px; font-size: 14px; }
        .alert-error { background: #ffebee; color: #c62828; border: 1px solid #ef9a9a; }
        .alert-success { background: #e8f5e9; color: #2e7d32; border: 1px solid #a5d6a7; }
        .login-link { text-align: center; margin-top: 20px; color: #666; font-size: 14px; }
        .login-link a { color: #667eea; text-decoration: none; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Register</h1>
        <p class="subtitle">Create your account</p>
        {% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
        {% if success %}<div class="alert alert-success">{{ success }}</div>{% endif %}
        <form method="POST">
            <div class="form-group">
                <label>Admin Password *</label>
                <input type="password" name="admin_password" required placeholder="Enter admin password">
            </div>
            <div class="form-group">
                <label>Username *</label>
                <input type="text" name="username" required placeholder="Choose username">
            </div>
            <div class="form-group">
                <label>Password *</label>
                <input type="password" name="password" required placeholder="Create password">
            </div>
            <div class="form-group">
                <label>reCAPTCHA Site Key *</label>
                <input type="text" name="recaptcha_site_key" required placeholder="Your site key">
            </div>
            <div class="form-group">
                <label>reCAPTCHA Secret Key *</label>
                <input type="password" name="recaptcha_secret_key" required placeholder="Your secret key">
            </div>
            <div class="form-group">
                <label>Shortener API Token *</label>
                <input type="text" name="arolinks_api_token" required placeholder="Your API token">
            </div>
            <div class="form-group">
                <label>Shortener Domain *</label>
                <input type="text" name="shortener_domain" required placeholder="example.com">
            </div>
            <button type="submit">Create Account</button>
        </form>
        <div class="login-link">Already have an account? <a href="/login">Login</a> | <a href="/owner-login">Owner Login</a></div>
    </div>
</body>
</html>'''

LOGIN_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - URL Shortener</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 450px;
            width: 100%;
        }
        h1 { color: #333; margin-bottom: 10px; text-align: center; font-size: 32px; }
        .subtitle { text-align: center; color: #666; margin-bottom: 30px; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; color: #333; margin-bottom: 8px; font-weight: 600; font-size: 14px; }
        input[type="text"], input[type="password"] { 
            width: 100%; 
            padding: 12px 15px; 
            border: 2px solid #e0e0e0; 
            border-radius: 10px; 
            font-size: 14px; 
            transition: border-color 0.3s; 
        }
        input:focus { outline: none; border-color: #667eea; }
        .remember-me {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
            padding: 10px 0;
        }
        .remember-me input[type="checkbox"] {
            width: 18px;
            height: 18px;
            margin-right: 10px;
            cursor: pointer;
            accent-color: #667eea;
        }
        .remember-me label {
            margin: 0;
            cursor: pointer;
            font-weight: normal;
            user-select: none;
        }
        button {
            width: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4); }
        .alert-error { 
            padding: 15px; 
            border-radius: 10px; 
            margin-bottom: 20px; 
            background: #ffebee; 
            color: #c62828; 
            border: 1px solid #ef9a9a; 
            font-size: 14px; 
        }
        .login-link { text-align: center; margin-top: 20px; color: #666; font-size: 14px; }
        .login-link a { color: #667eea; text-decoration: none; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        <p class="subtitle">Access your dashboard</p>
        {% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
        <form method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required placeholder="Enter username">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required placeholder="Enter password">
            </div>
            <div class="remember-me">
                <input type="checkbox" id="remember_me" name="remember_me" value="yes" checked>
                <label for="remember_me">Remember me for 7 days</label>
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="login-link">Don't have an account? <a href="/register">Register</a> | <a href="/owner-login">Owner Login</a></div>
    </div>
</body>
</html>'''

OWNER_LOGIN_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Owner Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 450px;
            width: 100%;
        }
        h1 { color: #c0392b; margin-bottom: 10px; text-align: center; font-size: 32px; }
        .subtitle { text-align: center; color: #666; margin-bottom: 30px; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; color: #333; margin-bottom: 8px; font-weight: 600; font-size: 14px; }
        input { width: 100%; padding: 12px 15px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 14px; }
        input:focus { outline: none; border-color: #e74c3c; }
        button { width: 100%; background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; border: none; padding: 15px; border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer; }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(231, 76, 60, 0.4); }
        .alert-error { padding: 15px; border-radius: 10px; margin-bottom: 20px; background: #ffebee; color: #c62828; border: 1px solid #ef9a9a; }
        .login-link { text-align: center; margin-top: 20px; color: #666; font-size: 14px; }
        .login-link a { color: #e74c3c; text-decoration: none; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Owner Dashboard</h1>
        <p class="subtitle">Administrator Login</p>
        {% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
        <form method="POST">
            <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" required placeholder="Owner email">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required placeholder="Owner password">
            </div>
            <button type="submit">Login as Owner</button>
        </form>
        <div class="login-link"><a href="/login">Back to User Login</a></div>
    </div>
</body>
</html>'''

OWNER_DASHBOARD_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Owner Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; min-height: 100vh; }
        .navbar { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 20px 30px; display: flex; justify-content: space-between; align-items: center; }
        .navbar h1 { font-size: 24px; }
        .nav-right { display: flex; gap: 15px; }
        .nav-link { color: white; text-decoration: none; padding: 8px 15px; border-radius: 8px; }
        .nav-link:hover { background: rgba(255,255,255,0.2); }
        .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .stat-value { font-size: 36px; font-weight: bold; color: #e74c3c; margin: 10px 0; }
        .users-table { background: white; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
        .table-header { padding: 20px; border-bottom: 1px solid #f0f0f0; }
        .table-header h2 { font-size: 18px; color: #333; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f8f9fa; padding: 15px; text-align: left; font-weight: 600; color: #666; border-bottom: 2px solid #e0e0e0; }
        td { padding: 15px; border-bottom: 1px solid #f0f0f0; }
        tr:hover { background: #f8f9fa; }
        .action-btn { padding: 8px 15px; background: #e74c3c; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 12px; }
        .action-btn:hover { background: #c0392b; }
        .view-btn { background: #3498db; }
        .view-btn:hover { background: #2980b9; }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>Owner Dashboard</h1>
        <div class="nav-right">
            <a href="/owner-logout" class="nav-link">Logout</a>
        </div>
    </div>
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div style="font-size: 40px;">👥</div>
                <div>Total Users</div>
                <div class="stat-value">{{ total_stats.total_users }}</div>
            </div>
            <div class="stat-card">
                <div style="font-size: 40px;">✅</div>
                <div>Active Users</div>
                <div class="stat-value">{{ total_stats.active_users }}</div>
            </div>
            <div class="stat-card">
                <div style="font-size: 40px;">🔗</div>
                <div>Total Links</div>
                <div class="stat-value">{{ total_stats.total_links }}</div>
            </div>
            <div class="stat-card">
                <div style="font-size: 40px;">💰</div>
                <div>Total Platform Earnings</div>
                <div class="stat-value">${{ "%.2f"|format(total_stats.total_earnings) }}</div>
            </div>
        </div>

        <div class="users-table">
            <div class="table-header">
                <h2>All Users</h2>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Status</th>
                        <th>Created At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.username }}</td>
                        <td><span style="padding: 4px 12px; border-radius: 20px; {% if user.status == 'active' %}background: #d4edda; color: #155724;{% else %}background: #f8d7da; color: #721c24;{% endif %}font-weight: 600; font-size: 12px;">{{ user.status }}</span></td>
                        <td>{{ user.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
                        <td>
                            <a href="/owner/user/{{ user.username }}" class="action-btn view-btn">View Details</a>
                            <button class="action-btn" onclick="disableUser('{{ user.username }}')">Disable</button>
                            <button class="action-btn" onclick="deleteUser('{{ user.username }}')">Delete</button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function disableUser(username) {
            if (confirm(`Disable user ${username}?`)) {
                fetch(`/owner/user/${username}/disable`, { method: 'POST' })
                    .then(r => r.json())
                    .then(d => { alert(d.message); location.reload(); });
            }
        }
        function deleteUser(username) {
            if (confirm(`Permanently delete user ${username} and ALL their links?`)) {
                fetch(`/owner/user/${username}/delete`, { method: 'POST' })
                    .then(r => r.json())
                    .then(d => { alert(d.message); location.reload(); });
            }
        }
    </script>
</body>
</html>'''

OWNER_USER_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Details - {{ user.username }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; min-height: 100vh; }
        .navbar { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; padding: 20px 30px; display: flex; justify-content: space-between; align-items: center; }
        .navbar h1 { font-size: 20px; }
        .nav-link { color: white; text-decoration: none; padding: 8px 15px; border-radius: 8px; }
        .nav-link:hover { background: rgba(255,255,255,0.2); }
        .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
        .card { background: white; padding: 25px; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .card h2 { margin-bottom: 20px; color: #333; border-bottom: 2px solid #e74c3c; padding-bottom: 10px; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .info-item { }
        .info-label { font-weight: 600; color: #666; font-size: 12px; text-transform: uppercase; }
        .info-value { font-size: 18px; color: #333; margin-top: 5px; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }
        .stat { background: #f8f9fa; padding: 15px; border-radius: 10px; text-align: center; }
        .stat-num { font-size: 28px; font-weight: bold; color: #e74c3c; }
        .stat-label { font-size: 12px; color: #666; margin-top: 5px; }
        .danger-btn { background: #e74c3c; color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; }
        .danger-btn:hover { background: #c0392b; }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>User: {{ user.username }}</h1>
        <div>
            <a href="/owner-dashboard" class="nav-link">Back</a>
            <a href="/owner-logout" class="nav-link">Logout</a>
        </div>
    </div>
    <div class="container">
        <div class="card">
            <h2>User Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Username</div>
                    <div class="info-value">{{ user.username }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Status</div>
                    <div class="info-value" style="{% if user.status == 'active' %}color: #28a745;{% else %}color: #dc3545;{% endif %}">{{ user.status }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Created At</div>
                    <div class="info-value">{{ user.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">API Key</div>
                    <div class="info-value" style="font-size: 12px; font-family: monospace;">{{ user.api_key[:20] }}...</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Statistics</h2>
            <div class="stat-grid">
                <div class="stat">
                    <div class="stat-num">{{ stats.total_links }}</div>
                    <div class="stat-label">Total Links</div>
                </div>
                <div class="stat">
                    <div class="stat-num">{{ stats.active_links }}</div>
                    <div class="stat-label">Active Links</div>
                </div>
                <div class="stat">
                    <div class="stat-num">{{ stats.used_links }}</div>
                    <div class="stat-label">Used Links</div>
                </div>
                <div class="stat">
                    <div class="stat-num">{{ stats.bypassed_links }}</div>
                    <div class="stat-label">Bypassed</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Earnings</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Today</div>
                    <div class="info-value">${{ "%.2f"|format(earnings.daily.total_earnings) }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">This Month</div>
                    <div class="info-value">${{ "%.2f"|format(earnings.monthly.total_earnings) }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Lifetime</div>
                    <div class="info-value">${{ "%.2f"|format(earnings.lifetime.total_earnings) }}</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Actions</h2>
            <button class="danger-btn" onclick="deleteUser('{{ user.username }}')">Delete User & All Links</button>
        </div>
    </div>

    <script>
        function deleteUser(username) {
            if (confirm(`Permanently delete ${username} and ALL their links?`)) {
                fetch(`/owner/user/${username}/delete`, { method: 'POST' })
                    .then(r => r.json())
                    .then(d => { alert(d.message); window.location.href = '/owner-dashboard'; });
            }
        }
    </script>
</body>
</html>'''

SETTINGS_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; min-height: 100vh; }
        .navbar { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .navbar h1 { font-size: 24px; }
        .navbar-right { display: flex; gap: 15px; }
        .nav-link { color: white; text-decoration: none; padding: 8px 15px; border-radius: 8px; transition: background 0.3s; }
        .nav-link:hover { background: rgba(255,255,255,0.2); }
        .container { max-width: 700px; margin: 30px auto; padding: 0 20px; }
        .card { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h2 { color: #333; margin-bottom: 20px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; color: #333; margin-bottom: 8px; font-weight: 600; font-size: 14px; }
        input, select { width: 100%; padding: 12px 15px; border: 2px solid #e0e0e0; border-radius: 10px; font-size: 14px; transition: border-color 0.3s; }
        input:focus, select:focus { outline: none; border-color: #667eea; }
        .checkbox-group { display: flex; align-items: center; gap: 10px; }
        .checkbox-group input { width: auto; }
        .helper-text { font-size: 12px; color: #999; margin-top: 5px; }
        button { width: 100%; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 15px; border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4); }
        .alert { padding: 15px; border-radius: 10px; margin-bottom: 20px; font-size: 14px; }
        .alert-error { background: #ffebee; color: #c62828; border: 1px solid #ef9a9a; }
        .alert-success { background: #e8f5e9; color: #2e7d32; border: 1px solid #a5d6a7; }
        .section-title { font-size: 16px; font-weight: 600; margin-top: 25px; margin-bottom: 15px; color: #667eea; border-top: 2px solid #f0f0f0; padding-top: 15px; }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>Settings</h1>
        <div class="navbar-right">
            <a href="/dashboard" class="nav-link">Dashboard</a>
            <a href="/analytics" class="nav-link">Analytics</a>
            <a href="/api-docs" class="nav-link">API Docs</a>
            <a href="/logout" class="nav-link">Logout</a>
        </div>
    </div>
    <div class="container">
        <div class="card">
            {% if error %}<div class="alert alert-error">{{ error }}</div>{% endif %}
            {% if success %}<div class="alert alert-success">{{ success }}</div>{% endif %}
            
            <h2>API Configuration</h2>
            <form method="POST">
                <div class="form-group">
                    <label>reCAPTCHA Site Key</label>
                    <input type="text" name="recaptcha_site_key" value="{{ user.recaptcha_site_key }}" required>
                </div>
                <div class="form-group">
                    <label>reCAPTCHA Secret Key</label>
                    <input type="password" name="recaptcha_secret_key" value="{{ user.recaptcha_secret_key }}" required>
                </div>
                <div class="form-group">
                    <label>URL Shortener API Token</label>
                    <input type="text" name="arolinks_api_token" value="{{ user.arolinks_api_token }}" required>
                </div>
                <div class="form-group">
                    <label>Shortener Domain</label>
                    <input type="text" name="shortener_domain" value="{{ user.shortener_domain }}" required>
                </div>

                <div class="section-title">Security Settings</div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="recaptcha_on_start" {% if user.get('settings', {}).get('recaptcha_on_start', False) %}checked{% endif %}>
                        <span>Enable reCAPTCHA on Start Page</span>
                    </label>
                    <div class="helper-text">Show reCAPTCHA verification before redirecting from /start/ page</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="recaptcha_on_verify" {% if user.get('settings', {}).get('recaptcha_on_verify', True) %}checked{% endif %}>
                        <span>Enable reCAPTCHA on Verify Page</span>
                    </label>
                    <div class="helper-text">Show reCAPTCHA verification on /verify/ page before final redirect</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="disable_link_after_use" {% if user.get('settings', {}).get('disable_link_after_use', True) %}checked{% endif %}>
                        <span>Disable Link After Initial Use</span>
                    </label>
                    <div class="helper-text">Mark link as "used" after successful verification (uncheck to allow reuse)</div>
                </div>
                
                <div class="form-group">
                    <label>Minimum Verification Time (seconds)</label>
                    <input type="number" name="verification_time_seconds" value="{{ user.get('settings', {}).get('verification_time_seconds', 0) }}" min="0" placeholder="0 for disabled">
                    <div class="helper-text">Minimum time user must spend before completing captcha. 0 = disabled</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="enable_verification_time_check" {% if user.get('settings', {}).get('enable_verification_time_check', True) %}checked{% endif %}>
                        <span>Enable Verification Time Check</span>
                    </label>
                    <div class="helper-text">Enforce minimum verification time requirement</div>
                </div>
                
                <div class="form-group">
                    <label>Auto-Disable Link After (hours)</label>
                    <input type="number" name="auto_disable_hours" value="{{ user.get('settings', {}).get('auto_disable_hours', 0) }}" min="0" placeholder="0 for disabled">
                    <div class="helper-text">Auto disable unused links after this many hours. 0 = disabled</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="check_fingerprint" {% if user.get('settings', {}).get('check_fingerprint', True) %}checked{% endif %}>
                        <span>Check Browser Fingerprint</span>
                    </label>
                    <div class="helper-text">Detects if user changes browser/device</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="enable_fingerprint_check" {% if user.get('settings', {}).get('enable_fingerprint_check', True) %}checked{% endif %}>
                        <span>Enable Fingerprint Check</span>
                    </label>
                    <div class="helper-text">Turn on/off fingerprint validation</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="check_cookies" {% if user.get('settings', {}).get('check_cookies', True) %}checked{% endif %}>
                        <span>Check Cookies</span>
                    </label>
                    <div class="helper-text">Validates cookie consistency</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="enable_cookie_check" {% if user.get('settings', {}).get('enable_cookie_check', True) %}checked{% endif %}>
                        <span>Enable Cookie Check</span>
                    </label>
                    <div class="helper-text">Turn on/off cookie validation</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="auto_delete_disabled" {% if user.get('settings', {}).get('auto_delete_disabled', False) %}checked{% endif %}>
                        <span>Auto-Delete Disabled Links</span>
                    </label>
                    <div class="helper-text">Automatically remove links after they are disabled</div>
                </div>

                <div class="section-title">🔒 Link Blocking Settings</div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="block_after_first_visit" {% if user.get('settings', {}).get('block_after_first_visit', True) %}checked{% endif %}>
                        <span>Block After First Visit</span>
                    </label>
                    <div class="helper-text">Block /start/ page after first visit (stores visitor details)</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="block_after_bypass" {% if user.get('settings', {}).get('block_after_bypass', True) %}checked{% endif %}>
                        <span>Block After Bypass Detected</span>
                    </label>
                    <div class="helper-text">Permanently block link when bypass attempt is detected</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="block_after_verify_complete" {% if user.get('settings', {}).get('block_after_verify_complete', True) %}checked{% endif %}>
                        <span>Block After Verify Complete</span>
                    </label>
                    <div class="helper-text">Block link after successful verification (one-time use)</div>
                </div>

                <div class="section-title">👁️ Visitor Tracking Settings</div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="store_visitor_details" {% if user.get('settings', {}).get('store_visitor_details', True) %}checked{% endif %}>
                        <span>Store Visitor Details</span>
                    </label>
                    <div class="helper-text">Store visitor IP, user-agent, and timestamp on first visit</div>
                </div>
                
                <div class="form-group">
                    <label>Max Visits Allowed</label>
                    <input type="number" name="max_visits_allowed" value="{{ user.get('settings', {}).get('max_visits_allowed', 1) }}" min="0" placeholder="1">
                    <div class="helper-text">Maximum visits before blocking. 0 = unlimited visits</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="require_same_ip" {% if user.get('settings', {}).get('require_same_ip', False) %}checked{% endif %}>
                        <span>Require Same IP</span>
                    </label>
                    <div class="helper-text">Block if IP changes between /start/ and /verify/ pages</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="check_shortener_referer" {% if user.get('settings', {}).get('check_shortener_referer', True) %}checked{% endif %}>
                        <span>Check Shortener Referer</span>
                    </label>
                    <div class="helper-text">Verify user came from shortener's "Get Link" button (blocks direct access)</div>
                </div>
                
                <div class="form-group">
                    <label class="checkbox-group">
                        <input type="checkbox" name="show_visit_count" {% if user.get('settings', {}).get('show_visit_count', True) %}checked{% endif %}>
                        <span>Track Visit Count</span>
                    </label>
                    <div class="helper-text">Track and store visit count for each link</div>
                </div>

                <div class="section-title">Account</div>
                <div class="form-group">
                    <label>New Password (Optional)</label>
                    <input type="password" name="new_password" placeholder="Leave blank to keep current">
                </div>
                <button type="submit">Save Changes</button>
            </form>
        </div>
    </div>
</body>
</html>'''

DASHBOARD_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; min-height: 100vh; }
        .navbar { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .navbar h1 { font-size: 24px; }
        .navbar-right { display: flex; gap: 15px; align-items: center; }
        .nav-link { color: white; text-decoration: none; padding: 8px 15px; border-radius: 8px; transition: background 0.3s; font-size: 14px; }
        .nav-link:hover { background: rgba(255,255,255,0.2); }
        .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .welcome-card { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .stat-icon { font-size: 40px; margin-bottom: 10px; }
        .stat-value { font-size: 32px; font-weight: bold; color: #667eea; margin-bottom: 5px; }
        .stat-label { color: #666; font-size: 14px; }
        .quick-links { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .quick-link-card { background: white; padding: 20px; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; text-decoration: none; color: #333; transition: transform 0.3s; }
        .quick-link-card:hover { transform: translateY(-5px); }
        .quick-link-icon { font-size: 35px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>📊 Dashboard</h1>
        <div class="navbar-right">
            <span>👤 {{ user.username }}</span>
            <a href="/analytics" class="nav-link">Analytics</a>
            <a href="/api-docs" class="nav-link">API Docs</a>
            <a href="/settings" class="nav-link">Settings</a>
            <a href="/logout" class="nav-link">Logout</a>
        </div>
    </div>
    <div class="container">
        <div class="welcome-card">
            <h2>Welcome back, {{ user.username }}! 👋</h2>
            <p>Your API Key: <code style="background: #f0f0f0; padding: 5px 10px; border-radius: 5px; font-family: monospace;">{{ user.api_key }}</code></p>
        </div>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">📊</div>
                <div class="stat-value">{{ stats.total_links }}</div>
                <div class="stat-label">Total Links</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">✅</div>
                <div class="stat-value">{{ stats.active_links }}</div>
                <div class="stat-label">Active Links</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">🎯</div>
                <div class="stat-value">{{ stats.used_links }}</div>
                <div class="stat-label">Used Links</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">🚫</div>
                <div class="stat-value">{{ stats.bypassed_links }}</div>
                <div class="stat-label">Bypassed</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">⏸️</div>
                <div class="stat-value">{{ stats.disabled_links }}</div>
                <div class="stat-label">Disabled</div>
            </div>
        </div>
        <h3 style="margin-bottom: 15px;">Quick Actions</h3>
        <div class="quick-links">
            <a href="/analytics" class="quick-link-card">
                <div class="quick-link-icon">📈</div>
                <div>Analytics</div>
            </a>
            <a href="/settings" class="quick-link-card">
                <div class="quick-link-icon">⚙️</div>
                <div>Settings</div>
            </a>
        </div>
    </div>
</body>
</html>'''

CAPTCHA_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify You're Human</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
        .container { background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); padding: 40px; max-width: 500px; width: 100%; text-align: center; }
        h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
        p { color: #666; margin-bottom: 30px; }
        .captcha-wrapper { display: flex; justify-content: center; margin: 30px 0; }
        button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 15px 40px; border-radius: 30px; font-size: 16px; font-weight: 600; cursor: pointer; width: 100%; max-width: 300px; }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4); }
        button:disabled { background: #ccc; cursor: not-allowed; }
        .loading { display: none; margin-top: 20px; color: #667eea; }
        .error { color: #e74c3c; margin-top: 20px; padding: 15px; background: #ffebee; border-radius: 10px; display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div style="font-size: 60px; margin-bottom: 20px;">🛡️</div>
        <h1>Security Verification</h1>
        <p>Please verify that you're human to continue.</p>
        <div class="captcha-wrapper">
            <div class="g-recaptcha" data-sitekey="{{ site_key }}"></div>
        </div>
        <button id="verifyBtn" onclick="verifyAndRedirect()">Get Link</button>
        <div class="loading" id="loading"><p>⏳ Verifying...</p></div>
        <div class="error" id="error"></div>
    </div>
    <script>
        const token = "{{ encrypted_token }}";
        function verifyAndRedirect() {
            const recaptchaResponse = grecaptcha.getResponse();
            if (!recaptchaResponse) {
                showError('Please complete the reCAPTCHA verification');
                return;
            }
            const btn = document.getElementById('verifyBtn');
            const loading = document.getElementById('loading');
            btn.disabled = true;
            loading.style.display = 'block';
            fetch('/verify-captcha', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: token, recaptcha: recaptchaResponse })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    window.location.href = data.redirect_url;
                } else {
                    showError(data.message || 'Verification failed');
                    btn.disabled = false;
                    loading.style.display = 'none';
                    grecaptcha.reset();
                }
            })
            .catch(error => {
                showError('An error occurred. Please try again.');
                btn.disabled = false;
                loading.style.display = 'none';
                grecaptcha.reset();
            });
        }
        function showError(message) {
            const errorDiv = document.getElementById('error');
            errorDiv.innerHTML = message;
            errorDiv.style.display = 'block';
            setTimeout(() => { errorDiv.style.display = 'none'; }, 5000);
        }
    </script>
</body>
</html>'''

ERROR_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ error_title }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
        .container { background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); padding: 40px; max-width: 500px; width: 100%; text-align: center; }
        .error-icon { font-size: 80px; margin-bottom: 20px; }
        h1 { color: #333; margin-bottom: 15px; font-size: 28px; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">⚠️</div>
        <h1>{{ error_title }}</h1>
        <p>{{ error_message | safe }}</p>
    </div>
</body>
</html>'''

START_CAPTCHA_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify You're Human</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
        .container { background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); padding: 40px; max-width: 500px; width: 100%; text-align: center; }
        h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
        p { color: #666; margin-bottom: 30px; }
        .captcha-wrapper { display: flex; justify-content: center; margin: 30px 0; }
        button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 15px 40px; border-radius: 30px; font-size: 16px; font-weight: 600; cursor: pointer; width: 100%; max-width: 300px; transition: all 0.3s; }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4); }
        button:disabled { background: #ccc; cursor: not-allowed; transform: none; }
        .error { color: #dc3545; margin-top: 20px; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Check</h1>
        <p>Please verify you're human before proceeding</p>
        <div class="captcha-wrapper">
            <div class="g-recaptcha" data-sitekey="{{ site_key }}"></div>
        </div>
        <button onclick="verifyStartCaptcha()" id="continueBtn">Continue</button>
        <div class="error" id="error"></div>
    </div>

    <script>
        function verifyStartCaptcha() {
            const recaptchaResponse = grecaptcha.getResponse();
            
            if (!recaptchaResponse) {
                document.getElementById('error').textContent = 'Please complete the reCAPTCHA';
                return;
            }

            const btn = document.getElementById('continueBtn');
            btn.disabled = true;
            btn.textContent = 'Verifying...';

            fetch('/verify-start-captcha', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token: '{{ encrypted_token }}',
                    recaptcha: recaptchaResponse
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    window.location.href = data.redirect_url;
                } else {
                    document.getElementById('error').textContent = data.message || 'Verification failed';
                    btn.disabled = false;
                    btn.textContent = 'Continue';
                    grecaptcha.reset();
                }
            })
            .catch(error => {
                document.getElementById('error').textContent = 'An error occurred';
                btn.disabled = false;
                btn.textContent = 'Continue';
                grecaptcha.reset();
            });
        }
    </script>
</body>
</html>'''

BROWSER_RESTRICTION_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Browser Not Supported</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            min-height: 100vh; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            padding: 20px; 
        }
        .container { 
            background: white; 
            border-radius: 25px; 
            box-shadow: 0 25px 70px rgba(0,0,0,0.3); 
            padding: 50px 40px; 
            max-width: 600px; 
            width: 100%; 
            text-align: center; 
            animation: slideIn 0.5s ease-out;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .icon { 
            font-size: 100px; 
            margin-bottom: 20px; 
            animation: bounce 2s infinite;
        }
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }
        h1 { 
            color: #333; 
            margin-bottom: 15px; 
            font-size: 32px; 
            font-weight: 700;
        }
        p { 
            color: #666; 
            line-height: 1.8; 
            margin-bottom: 30px; 
            font-size: 16px;
        }
        .browsers {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin: 40px 0;
            flex-wrap: wrap;
        }
        .browser-card {
            background: #f8f9fa;
            border-radius: 15px;
            padding: 25px 20px;
            width: 180px;
            transition: all 0.3s ease;
            cursor: pointer;
            text-decoration: none;
            color: inherit;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .browser-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 15px 30px rgba(0,0,0,0.2);
        }
        .browser-icon {
            font-size: 60px;
            margin-bottom: 15px;
        }
        .browser-name {
            font-weight: 600;
            color: #333;
            font-size: 18px;
            margin-bottom: 8px;
        }
        .browser-desc {
            font-size: 12px;
            color: #999;
        }
        .chrome-card:hover {
            background: linear-gradient(135deg, #ffeaa7 0%, #fdcb6e 100%);
        }
        .edge-card:hover {
            background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
        }
        .note {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 8px;
            margin-top: 30px;
            text-align: left;
        }
        .note-title {
            font-weight: 600;
            color: #856404;
            margin-bottom: 5px;
        }
        .note-text {
            color: #856404;
            font-size: 14px;
            margin: 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🚫</div>
        <h1>Browser Not Supported</h1>
        <p>For the best experience and security, this service only works with <strong>Google Chrome</strong> or <strong>Microsoft Edge</strong> browsers.</p>
        
        <div class="browsers">
            <a href="https://www.google.com/chrome/" target="_blank" class="browser-card chrome-card">
                <div class="browser-icon">🌐</div>
                <div class="browser-name">Google Chrome</div>
                <div class="browser-desc">Fast & Secure</div>
            </a>
            
            <a href="https://www.microsoft.com/edge" target="_blank" class="browser-card edge-card">
                <div class="browser-icon">🔷</div>
                <div class="browser-name">Microsoft Edge</div>
                <div class="browser-desc">Built on Chromium</div>
            </a>
        </div>
        
        <div class="note">
            <div class="note-title">💡 Why Chrome or Edge?</div>
            <p class="note-text">These browsers provide the security features and compatibility required for our verification system to work properly.</p>
        </div>
    </div>
</body>
</html>'''

API_DOCS_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Documentation - URL Shortener</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #f5f7fa;
            line-height: 1.6;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 60px 20px;
            text-align: center;
        }
        .header h1 {
            font-size: 48px;
            margin-bottom: 10px;
        }
        .header p {
            font-size: 18px;
            opacity: 0.9;
        }
        .container {
            max-width: 1200px;
            margin: -40px auto 40px;
            padding: 0 20px;
        }
        .card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            padding: 40px;
            margin-bottom: 30px;
        }
        h2 {
            color: #333;
            font-size: 32px;
            margin-bottom: 20px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        h3 {
            color: #667eea;
            font-size: 24px;
            margin: 30px 0 15px;
        }
        .endpoint {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .method {
            display: inline-block;
            background: #28a745;
            color: white;
            padding: 5px 15px;
            border-radius: 5px;
            font-weight: 600;
            margin-right: 10px;
            font-size: 14px;
        }
        .method.post { background: #007bff; }
        .url {
            font-family: 'Courier New', monospace;
            color: #333;
            font-size: 16px;
        }
        .code-block {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
        }
        .code-block .key { color: #66d9ef; }
        .code-block .string { color: #a6e22e; }
        .code-block .number { color: #ae81ff; }
        .code-block .comment { color: #75715e; font-style: italic; }
        .param-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .param-table th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        .param-table td {
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        .param-table tr:hover {
            background: #f8f9fa;
        }
        .required {
            color: #dc3545;
            font-weight: 600;
        }
        .optional {
            color: #28a745;
            font-weight: 600;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin-left: 10px;
        }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-error { background: #f8d7da; color: #721c24; }
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .feature-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
        }
        .feature-icon {
            font-size: 48px;
            margin-bottom: 15px;
        }
        .feature-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 10px;
        }
        .feature-desc {
            font-size: 14px;
            opacity: 0.9;
        }
        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid;
        }
        .alert-info {
            background: #d1ecf1;
            border-color: #0c5460;
            color: #0c5460;
        }
        .alert-warning {
            background: #fff3cd;
            border-color: #856404;
            color: #856404;
        }
        .copy-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            margin-top: 10px;
        }
        .copy-btn:hover {
            background: #5568d3;
        }
        .try-it {
            background: #28a745;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            margin-top: 20px;
        }
        .try-it:hover {
            background: #218838;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔗 API Documentation</h1>
        <p>Secure URL Shortener with Advanced Protection</p>
    </div>

    <div class="container">
        <!-- Quick Start -->
        <div class="card">
            <h2>🚀 Quick Start</h2>
            <p>Get started with our API in minutes. Create secure, trackable short links with advanced bypass protection.</p>
            
            <div class="alert alert-info">
                <strong>📌 Base URL:</strong> <code>{{ app_url }}</code>
            </div>

            <div class="alert alert-info">
                <strong>🔑 Your API Key:</strong> <code style="user-select: all;">{{ user.api_key }}</code>
            </div>

            <h3>Get Started</h3>
            <p>Your API key is already included in all the code examples below. Just copy and use them!</p>
        </div>

        <!-- Security Features -->
        <div class="card">
            <h2>🛡️ Security Features</h2>
            <div class="feature-grid">
                <div class="feature-card">
                    <div class="feature-icon">🔒</div>
                    <div class="feature-title">Dynamic Verify URLs</div>
                    <div class="feature-desc">Unique, unpredictable tokens prevent URL manipulation</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🌐</div>
                    <div class="feature-title">Browser Restriction</div>
                    <div class="feature-desc">Chrome & Edge only for enhanced security</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">👤</div>
                    <div class="feature-title">Fingerprint Check</div>
                    <div class="feature-desc">Detects browser/device changes</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🍪</div>
                    <div class="feature-title">Cookie Validation</div>
                    <div class="feature-desc">Ensures session consistency</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">⏱️</div>
                    <div class="feature-title">Time Verification</div>
                    <div class="feature-desc">Minimum time requirements</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🤖</div>
                    <div class="feature-title">reCAPTCHA</div>
                    <div class="feature-desc">Bot protection on start & verify</div>
                </div>
            </div>
        </div>

        <!-- Create Link Endpoint -->
        <div class="card">
            <h2>📝 Create Short Link</h2>
            
            <div class="endpoint">
                <span class="method">GET</span>
                <span class="method post">POST</span>
                <span class="url">/api/create</span>
            </div>

            <h3>Parameters</h3>
            <table class="param-table">
                <thead>
                    <tr>
                        <th>Parameter</th>
                        <th>Type</th>
                        <th>Required</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><code>api</code></td>
                        <td>string</td>
                        <td><span class="required">Required</span></td>
                        <td>Your API key from dashboard</td>
                    </tr>
                    <tr>
                        <td><code>url</code></td>
                        <td>string</td>
                        <td><span class="required">Required</span></td>
                        <td>The original URL to shorten</td>
                    </tr>
                </tbody>
            </table>

            <h3>Example Request (GET)</h3>
            <div class="code-block">
<span class="comment"># Using cURL</span>
curl "{{ app_url }}/api/create?api={{ user.api_key }}&url=https://example.com"

<span class="comment"># Using JavaScript (fetch)</span>
fetch('{{ app_url }}/api/create?api={{ user.api_key }}&url=https://example.com')
  .then(response => response.json())
  .then(data => console.log(data));
            </div>

            <h3>Example Request (POST)</h3>
            <div class="code-block">
<span class="comment"># Using cURL</span>
curl -X POST {{ app_url }}/api/create \
  -H "Content-Type: application/json" \
  -d '{
    <span class="key">"api"</span>: <span class="string">"{{ user.api_key }}"</span>,
    <span class="key">"url"</span>: <span class="string">"https://example.com"</span>
  }'

<span class="comment"># Using JavaScript (fetch)</span>
fetch('{{ app_url }}/api/create', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    api: '{{ user.api_key }}',
    url: 'https://example.com'
  })
})
.then(response => response.json())
.then(data => console.log(data));

<span class="comment"># Using Python (requests)</span>
import requests

response = requests.post('{{ app_url }}/api/create', json={
    'api': '{{ user.api_key }}',
    'url': 'https://example.com'
})
print(response.json())
            </div>

            <h3>Success Response <span class="badge badge-success">200 OK</span></h3>
            <div class="code-block">
{
  <span class="key">"status"</span>: <span class="string">"success"</span>,
  <span class="key">"shortenedUrl"</span>: <span class="string">"{{ app_url }}/start/gAAAAABpCHMJ..."</span>,
  <span class="key">"original_url"</span>: <span class="string">"https://example.com"</span>
}
            </div>

            <h3>Error Responses</h3>
            <div class="code-block">
<span class="comment"># Invalid API Key</span> <span class="badge badge-error">401 Unauthorized</span>
{
  <span class="key">"status"</span>: <span class="string">"error"</span>,
  <span class="key">"message"</span>: <span class="string">"Invalid or missing API key"</span>
}

<span class="comment"># Missing URL</span> <span class="badge badge-error">400 Bad Request</span>
{
  <span class="key">"status"</span>: <span class="string">"error"</span>,
  <span class="key">"message"</span>: <span class="string">"URL parameter is required"</span>
}

<span class="comment"># Shortener API Error</span> <span class="badge badge-error">400 Bad Request</span>
{
  <span class="key">"status"</span>: <span class="string">"error"</span>,
  <span class="key">"message"</span>: <span class="string">"Shortener API error: ..."</span>
}
            </div>
        </div>

        <!-- How It Works -->
        <div class="card">
            <h2>⚙️ How It Works</h2>
            
            <h3>1. Link Creation</h3>
            <p>When you create a link via API:</p>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>✅ Two unique tokens are generated (encrypted_token & verify_token)</li>
                <li>✅ verify_token is embedded in the arolinks shortened URL</li>
                <li>✅ You receive a /start/ URL to share with users</li>
            </ul>

            <h3>2. User Flow</h3>
            <div class="code-block">
User clicks: {{ app_url }}/start/{encrypted_token}
    ↓
Browser check (Chrome/Edge only)
    ↓
Redirects to: arolinks shortened URL
    ↓
Arolinks redirects to: {{ app_url }}/verify/{verify_token}
    ↓
Browser check + Security checks
    ↓
reCAPTCHA verification (if enabled)
    ↓
Redirects to: Original URL
            </div>

            <h3>3. Security Checks</h3>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>🔒 Browser must be Chrome or Edge</li>
                <li>🔒 /start/ must be accessed before /verify/</li>
                <li>🔒 verify_token must match database</li>
                <li>🔒 Fingerprint validation (if enabled)</li>
                <li>🔒 Cookie consistency check (if enabled)</li>
                <li>🔒 Minimum verification time (if enabled)</li>
                <li>🔒 reCAPTCHA verification (if enabled)</li>
            </ul>

            <div class="alert alert-warning">
                <strong>⚠️ Bypass Protection:</strong> If any security check fails, the link is marked as "bypassed" and permanently disabled. Users cannot reuse bypassed links.
            </div>
        </div>

        <!-- Settings Control -->
        <div class="card">
            <h2>⚙️ Configurable Settings</h2>
            <p>All security features can be controlled from your dashboard settings:</p>
            
            <table class="param-table">
                <thead>
                    <tr>
                        <th>Setting</th>
                        <th>Default</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Disable Link After Use</td>
                        <td>ON</td>
                        <td>Mark link as "used" after successful verification</td>
                    </tr>
                    <tr>
                        <td>reCAPTCHA on Start</td>
                        <td>OFF</td>
                        <td>Show reCAPTCHA before redirecting from /start/</td>
                    </tr>
                    <tr>
                        <td>reCAPTCHA on Verify</td>
                        <td>ON</td>
                        <td>Show reCAPTCHA on /verify/ page</td>
                    </tr>
                    <tr>
                        <td>Enable Fingerprint Check</td>
                        <td>ON</td>
                        <td>Validate browser fingerprint consistency</td>
                    </tr>
                    <tr>
                        <td>Enable Cookie Check</td>
                        <td>ON</td>
                        <td>Validate cookie consistency</td>
                    </tr>
                    <tr>
                        <td>Enable Verification Time</td>
                        <td>ON</td>
                        <td>Enforce minimum verification time</td>
                    </tr>
                    <tr>
                        <td>Auto-Disable After Hours</td>
                        <td>0 (disabled)</td>
                        <td>Automatically disable unused links</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <!-- Rate Limits -->
        <div class="card">
            <h2>📊 Best Practices</h2>
            <ul style="margin-left: 20px;">
                <li>✅ Store your API key securely (never expose in client-side code)</li>
                <li>✅ Use HTTPS for all API requests</li>
                <li>✅ Handle errors gracefully in your application</li>
                <li>✅ Monitor your analytics dashboard for bypass attempts</li>
                <li>✅ Configure security settings based on your use case</li>
                <li>✅ Regenerate links if you suspect compromise</li>
            </ul>
        </div>

        <!-- Support -->
        <div class="card">
            <h2>💬 Need Help?</h2>
            <p>If you have questions or need assistance:</p>
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>📧 Contact your account administrator</li>
                <li>📊 Check your analytics dashboard for link status</li>
                <li>⚙️ Review your settings configuration</li>
            </ul>
        </div>
    </div>

    <div style="text-align: center; padding: 40px 20px; color: #666;">
        <p>Made with ❤️ by Anime Sentinall Team</p>
    </div>
</body>
</html>'''

ANALYTICS_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analytics Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; min-height: 100vh; }
        .navbar { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .navbar h1 { font-size: 24px; }
        .navbar-right { display: flex; gap: 15px; }
        .nav-link { color: white; text-decoration: none; padding: 8px 15px; border-radius: 8px; transition: background 0.3s; }
        .nav-link:hover { background: rgba(255,255,255,0.2); }
        .container { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-left: 4px solid #667eea; }
        .stat-label { color: #666; font-size: 14px; font-weight: 600; margin-bottom: 10px; text-transform: uppercase; }
        .stat-value { font-size: 32px; font-weight: bold; color: #333; margin-bottom: 5px; }
        .stat-sub { color: #999; font-size: 12px; }
        .controls { background: white; padding: 20px; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 30px; display: flex; gap: 15px; align-items: center; }
        .month-selector { padding: 10px 15px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; cursor: pointer; }
        .tabs { display: flex; gap: 10px; background: white; padding: 15px; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .tab-btn { padding: 10px 20px; border: none; background: #f0f0f0; border-radius: 8px; cursor: pointer; font-weight: 600; transition: all 0.3s; }
        .tab-btn.active { background: #667eea; color: white; }
        .table-card { background: white; border-radius: 15px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
        .table-header { padding: 20px; border-bottom: 1px solid #f0f0f0; }
        .table-header h3 { font-size: 18px; color: #333; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f8f9fa; padding: 15px; text-align: left; font-weight: 600; color: #666; border-bottom: 2px solid #e0e0e0; font-size: 13px; }
        td { padding: 15px; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
        tr:hover { background: #f8f9fa; }
        .loading { text-align: center; padding: 40px; color: #666; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .badge-completed { background: #d4edda; color: #155724; }
        .badge-bypassed { background: #f8d7da; color: #721c24; }
        .badge-active { background: #d1ecf1; color: #0c5460; }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>📊 Analytics Dashboard</h1>
        <div class="navbar-right">
            <a href="/dashboard" class="nav-link">Dashboard</a>
            <a href="/api-docs" class="nav-link">API Docs</a>
            <a href="/settings" class="nav-link">Settings</a>
            <a href="/logout" class="nav-link">Logout</a>
        </div>
    </div>

    <div class="container">
        <div id="summaryStats" class="stats-grid">
            <div class="loading">Loading analytics...</div>
        </div>

        <div class="controls">
            <label for="monthSelector">Select Month:</label>
            <select id="monthSelector" class="month-selector">
                <option value="">Loading months...</option>
            </select>
        </div>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('daily')">Daily Report</button>
            <button class="tab-btn" onclick="switchTab('monthly')">Monthly Report</button>
            <button class="tab-btn" onclick="switchTab('lifetime')">Lifetime Stats</button>
        </div>

        <div id="daily" class="tab-content active">
            <div class="table-card">
                <div class="table-header">
                    <h3>Daily Statistics</h3>
                </div>
                <div id="dailyTable" class="loading">Loading daily data...</div>
            </div>
        </div>

        <div id="monthly" class="tab-content">
            <div class="table-card">
                <div class="table-header">
                    <h3>Monthly Statistics (Last 12 Months)</h3>
                </div>
                <div id="monthlyTable" class="loading">Loading monthly data...</div>
            </div>
        </div>

        <div id="lifetime" class="tab-content">
            <div class="table-card">
                <div class="table-header">
                    <h3>Lifetime Statistics</h3>
                </div>
                <table>
                    <tbody id="lifetimeData">
                        <tr>
                            <td colspan="4" class="loading">Loading lifetime data...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        const appUrl = '{{ app_url }}';
        let summaryData = {};

        async function loadSummary() {
            try {
                const res = await fetch(`${appUrl}/api/analytics/summary`);
                const data = await res.json();
                if (data.status === 'success') {
                    summaryData = data;
                    renderSummary();
                    loadMonthlyData();
                }
            } catch (error) {
                console.error('Error loading summary:', error);
            }
        }

        function renderSummary() {
            const html = `
                <div class="stat-card">
                    <div class="stat-label">Today Created</div>
                    <div class="stat-value">${summaryData.daily.total_created}</div>
                    <div class="stat-sub">Completed: ${summaryData.daily.total_completed} | Bypassed: ${summaryData.daily.total_bypassed} | Active: ${summaryData.daily.total_active}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">This Month Created</div>
                    <div class="stat-value">${summaryData.monthly.total_created}</div>
                    <div class="stat-sub">Completed: ${summaryData.monthly.total_completed} | Bypassed: ${summaryData.monthly.total_bypassed} | Active: ${summaryData.monthly.total_active}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Lifetime Created</div>
                    <div class="stat-value">${summaryData.lifetime.total_created}</div>
                    <div class="stat-sub">Completed: ${summaryData.lifetime.total_completed} | Bypassed: ${summaryData.lifetime.total_bypassed} | Active: ${summaryData.lifetime.total_active}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Currently Active</div>
                    <div class="stat-value">${summaryData.lifetime.total_active}</div>
                    <div class="stat-sub">This Month: ${summaryData.monthly.total_active}</div>
                </div>
            `;
            document.getElementById('summaryStats').innerHTML = html;
        }

        async function loadMonthlyData() {
            try {
                const res = await fetch(`${appUrl}/api/analytics/monthly`);
                const data = await res.json();
                if (data.status === 'success') {
                    populateMonthSelector(data.data);
                    renderMonthlyTable(data.data);
                    renderLifetimeStats();
                    loadDailyData();
                }
            } catch (error) {
                console.error('Error loading monthly data:', error);
            }
        }

        function populateMonthSelector(months) {
            const selector = document.getElementById('monthSelector');
            const current = '{{ current_month }}';
            selector.innerHTML = months.map(m => 
                `<option value="${m.month}" ${m.month === current ? 'selected' : ''}>${m.display}</option>`
            ).join('');
            selector.onchange = () => loadDailyData();
        }

        async function loadDailyData() {
            const month = document.getElementById('monthSelector').value;
            if (!month) return;
            
            try {
                const res = await fetch(`${appUrl}/api/analytics/daily/${month}`);
                const data = await res.json();
                if (data.status === 'success') {
                    renderDailyTable(data.data);
                }
            } catch (error) {
                console.error('Error loading daily data:', error);
            }
        }

        function renderDailyTable(data) {
            const html = `
                <table>
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Created</th>
                            <th>Completed</th>
                            <th>Bypassed</th>
                            <th>Active</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.map(d => `
                            <tr>
                                <td>${d.date}</td>
                                <td>${d.created}</td>
                                <td><span class="badge badge-completed">${d.completed}</span></td>
                                <td><span class="badge badge-bypassed">${d.bypassed}</span></td>
                                <td><span class="badge badge-active">${d.active}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
            document.getElementById('dailyTable').innerHTML = html;
        }

        function renderMonthlyTable(data) {
            const html = `
                <table>
                    <thead>
                        <tr>
                            <th>Month</th>
                            <th>Created</th>
                            <th>Completed</th>
                            <th>Bypassed</th>
                            <th>Active</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.map(m => `
                            <tr>
                                <td>${m.display}</td>
                                <td>${m.created}</td>
                                <td><span class="badge badge-completed">${m.completed}</span></td>
                                <td><span class="badge badge-bypassed">${m.bypassed}</span></td>
                                <td><span class="badge badge-active">${m.active}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
            document.getElementById('monthlyTable').innerHTML = html;
        }

        function renderLifetimeStats() {
            const lifetime = summaryData.lifetime;
            const html = `
                <tr>
                    <td><strong>Total Links Created</strong></td>
                    <td>${lifetime.total_created}</td>
                </tr>
                <tr>
                    <td><strong>Successfully Completed</strong></td>
                    <td><span class="badge badge-completed">${lifetime.total_completed}</span></td>
                </tr>
                <tr>
                    <td><strong>Bypass Attempts Detected</strong></td>
                    <td><span class="badge badge-bypassed">${lifetime.total_bypassed}</span></td>
                </tr>
                <tr>
                    <td><strong>Currently Active</strong></td>
                    <td><span class="badge badge-active">${lifetime.total_active}</span></td>
                </tr>
            `;
            document.getElementById('lifetimeData').innerHTML = html;
        }

        function switchTab(tab) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tab).classList.add('active');
            event.target.classList.add('active');
        }

        loadSummary();
    </script>
</body>
</html>'''

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=True)

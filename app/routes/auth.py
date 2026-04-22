from flask import Blueprint, render_template, request, redirect, url_for, session, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
from ..models.user import create_user, get_user_by_username

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.form
            
            admin_pass = data.get('admin_password')
            if admin_pass != current_app.config['OWNER_PASSWORD']:
                return render_template('auth/register.html', 
                    error='Invalid admin password. Contact the owner for access.')
            
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            recaptcha_site_key = data.get('recaptcha_site_key', '').strip()
            recaptcha_secret_key = data.get('recaptcha_secret_key', '').strip()
            shortener_api_token = data.get('shortener_api_token', '').strip()
            shortener_domain = data.get('shortener_domain', '').strip()
            
            if not all([username, password, recaptcha_site_key, recaptcha_secret_key, shortener_api_token, shortener_domain]):
                return render_template('auth/register.html', 
                    error='All fields are required.')
            
            if get_user_by_username(username):
                return render_template('auth/register.html', 
                    error='Username already exists.')
            
            user_data = {
                'username': username,
                'password': generate_password_hash(password),
                'api_key': secrets.token_urlsafe(32),
                'recaptcha_site_key': recaptcha_site_key,
                'recaptcha_secret_key': recaptcha_secret_key,
                'shortener_api_token': shortener_api_token,
                'shortener_domain': shortener_domain.replace('https://', '').replace('http://', ''),
                'created_at': datetime.utcnow(),
                'status': 'active',
                'settings': {
                    'verification_time_seconds': 0,
                    'auto_disable_hours': 0,
                    'check_fingerprint': True,
                    'check_cookies': True,
                    'auto_delete_disabled': False,
                    'disable_link_after_use': True,
                    'recaptcha_on_start': False,
                    'recaptcha_on_verify': True,
                    'enable_verification_time_check': True,
                    'enable_fingerprint_check': True,
                    'enable_cookie_check': True,
                    'block_after_first_visit': True,
                    'block_after_bypass': True,
                    'block_after_verify_complete': True,
                    'store_visitor_details': True,
                    'max_visits_allowed': 1,
                    'require_same_ip': False,
                    'check_shortener_referer': True,
                    'show_visit_count': True
                }
            }
            
            create_user(user_data)
            return render_template('auth/register.html', 
                success='Account created successfully! Please login.')
            
        except Exception as e:
            return render_template('auth/register.html', 
                error=f'Registration failed: {str(e)}')
    
    return render_template('auth/register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        remember_me = request.form.get('remember_me') == 'yes'
        
        user = get_user_by_username(username)
        
        if user and check_password_hash(user['password'], password):
            if user.get('status') != 'active':
                return render_template('auth/login.html', 
                    error='Your account has been disabled.')
            
            if remember_me:
                session.permanent = True
            else:
                session.permanent = False
            
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['logged_in'] = True
            session['remember_me'] = remember_me
            session.modified = True
            
            return redirect(url_for('dashboard.index'))
        else:
            return render_template('auth/login.html', 
                error='Invalid username or password.')
    
    return render_template('auth/login.html')

@auth_bp.route('/owner-login', methods=['GET', 'POST'])
def owner_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if email == current_app.config['OWNER_EMAIL'] and password == current_app.config['OWNER_PASSWORD']:
            session['owner_logged_in'] = True
            session['owner_email'] = email
            session.modified = True
            return redirect(url_for('admin.index'))
        else:
            return render_template('auth/owner_login.html', 
                error='Invalid email or password.')
    
    return render_template('auth/owner_login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

@auth_bp.route('/owner-logout')
def owner_logout():
    session.clear()
    return redirect(url_for('auth.owner_login'))

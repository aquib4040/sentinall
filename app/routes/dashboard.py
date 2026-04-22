from flask import Blueprint, render_template, request, redirect, url_for, session, current_app, jsonify
from datetime import datetime
from ..models.user import get_user_by_username, update_user_settings
from ..models.stats import get_user_stats
from ..models.link import auto_disable_old_links, delete_disabled_links
from ..utils.decorators import login_required
from werkzeug.security import generate_password_hash

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def index():
    username = session['username']
    user = get_user_by_username(username)
    stats = get_user_stats(username)
    
    # Auto-process based on user settings
    user_settings = user.get('settings', {})
    auto_disable_old_links(username, user_settings.get('auto_disable_hours', 0))
    if user_settings.get('auto_delete_disabled', False):
        delete_disabled_links(username)
    
    return render_template('dashboard/index.html', 
        user=user, 
        stats=stats)

@dashboard_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    username = session['username']
    user = get_user_by_username(username)
    
    if request.method == 'POST':
        try:
            updates = {
                'recaptcha_site_key': request.form.get('recaptcha_site_key', '').strip(),
                'recaptcha_secret_key': request.form.get('recaptcha_secret_key', '').strip(),
                'shortener_api_token': request.form.get('shortener_api_token', '').strip(),
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
                    'block_after_first_visit': request.form.get('block_after_first_visit') == 'on',
                    'block_after_bypass': request.form.get('block_after_bypass') == 'on',
                    'block_after_verify_complete': request.form.get('block_after_verify_complete') == 'on',
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
            
            update_user_settings(username, updates)
            
            return render_template('dashboard/settings.html', 
                user=get_user_by_username(username),
                success='Settings updated successfully!')
            
        except Exception as e:
            return render_template('dashboard/settings.html', 
                user=user,
                error=f'Update failed: {str(e)}')
    
    return render_template('dashboard/settings.html', user=user)

@dashboard_bp.route('/analytics')
@login_required
def analytics():
    username = session['username']
    user = get_user_by_username(username)
    current_month = datetime.utcnow().strftime('%Y-%m')
    
    return render_template('dashboard/analytics.html',
        user=user,
        current_month=current_month,
        app_url=request.url_root.rstrip('/'))

@dashboard_bp.route('/api-docs')
@login_required
def api_docs():
    username = session['username']
    user = get_user_by_username(username)
    app_url = request.url_root.rstrip('/')
    return render_template('dashboard/api_docs.html', app_url=app_url, user=user)

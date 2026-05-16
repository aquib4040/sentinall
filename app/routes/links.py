from flask import Blueprint, render_template, request, redirect, jsonify, current_app, session
from datetime import datetime, timedelta
import random
import secrets
import requests
from urllib.parse import urlparse
from ..models.link import get_link_by_token, get_link_by_verify_token, update_link_fingerprint, mark_link_bypassed, mark_link_used
from ..models.user import get_user_by_username
from ..utils.security import generate_fingerprint, get_cookie_data, is_allowed_browser, get_client_ip
from ..models.database import db

links_bp = Blueprint('links', __name__)

# ── In-memory one-time redirect tokens (expire after 30 seconds) ──
_redirect_tokens = {}

def _create_redirect_token(original_url):
    """Create a one-time token that maps to a URL. Never expose the URL in JSON."""
    token = secrets.token_urlsafe(48)
    _redirect_tokens[token] = {
        'url': original_url,
        'created_at': datetime.utcnow(),
        'used': False
    }
    # Purge expired tokens (older than 60 seconds)
    cutoff = datetime.utcnow() - timedelta(seconds=60)
    expired = [k for k, v in _redirect_tokens.items() if v['created_at'] < cutoff]
    for k in expired:
        del _redirect_tokens[k]
    return token

def _consume_redirect_token(token):
    """Consume a one-time redirect token. Returns URL or None."""
    entry = _redirect_tokens.get(token)
    if not entry:
        return None
    if entry['used']:
        return None
    if (datetime.utcnow() - entry['created_at']).total_seconds() > 30:
        del _redirect_tokens[token]
        return None
    entry['used'] = True
    url = entry['url']
    del _redirect_tokens[token]
    return url


@links_bp.route('/start/<encrypted_token>')
def start(encrypted_token):
    try:
        if not is_allowed_browser():
            return render_template('link/browser_restriction.html')
        
        fingerprint = generate_fingerprint()
        cookie_data = get_cookie_data()
        
        visitor_ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        link = get_link_by_token(encrypted_token)
        
        if not link:
            return render_template('errors/404.html', 
                error_title="Link Not Found",
                error_message='This link does not exist or has expired.')
        
        if link.get('is_disabled', False):
            return render_template('errors/error.html',
                error_title="Link Disabled",
                error_message='This link has been disabled.')
        
        if link.get('is_bypassed', False):
            roast_titles = ['Nice Try Diddy! 🤡', 'Caught Lacking! 📸', 'You Thought! 💀', 'Not Today Fam! 🚫', 'L + Ratio 😂']
            stored_message = link.get('bypass_message', 'This link has been blocked. Better luck next time!')
            return render_template('errors/error.html',
                error_title=random.choice(roast_titles),
                error_message=stored_message)
        
        if link.get('status') == 'used':
            return render_template('errors/error.html',
                error_title="Link Already Used",
                error_message='This link has already been used.')
        
        user = get_user_by_username(link['username'])
        if not user:
            return render_template('errors/error.html',
                error_title="System Error",
                error_message="The owner of this link no longer exists.")
                
        user_settings = user.get('settings', {})
        
        max_visits = user_settings.get('max_visits_allowed', 1)
        current_visits = link.get('visit_count', 0)
        
        if max_visits > 0 and current_visits >= max_visits:
            return render_template('errors/error.html',
                error_title="Link Limit Reached",
                error_message=f'This link has reached its maximum visits limit ({max_visits}).')
        
        block_after_first_visit = user_settings.get('block_after_first_visit', True)
        if block_after_first_visit and link.get('initial_fingerprint') is not None:
            return render_template('errors/error.html',
                error_title="Invalid Access",
                error_message='This link has already been initialized. Please use the verification link OR Regenerate The Link.')
        
        if user_settings.get('auto_disable_hours', 0) > 0:
            hours = user_settings['auto_disable_hours']
            expiry_time = link['created_at'] + timedelta(hours=hours)
            if datetime.utcnow() > expiry_time:
                return render_template('errors/error.html',
                    error_title="Link Expired",
                    error_message=f'This link expired after {hours} hours.')
        
        recaptcha_on_start = user_settings.get('recaptcha_on_start', False)
        if recaptcha_on_start:
            return render_template('link/start_captcha.html',
                site_key=user['recaptcha_site_key'],
                encrypted_token=encrypted_token)
        
        update_link_fingerprint(
            encrypted_token, 
            {
                'initial_fingerprint': fingerprint,
                'initial_cookies': cookie_data
            }
        )
        
        update_data = {
            'verification_start_time': datetime.utcnow(),
            'start_accessed': True
        }
        
        if user_settings.get('store_visitor_details', True):
            update_data['visitor_ip'] = visitor_ip
            update_data['visitor_user_agent'] = user_agent
            update_data['first_visit_time'] = datetime.utcnow()
        
        if user_settings.get('show_visit_count', True):
            db.links.update_one(
                {'encrypted_token': encrypted_token},
                {
                    '$set': update_data,
                    '$inc': {'visit_count': 1}
                }
            )
        else:
            db.links.update_one(
                {'encrypted_token': encrypted_token},
                {'$set': update_data}
            )
        
        return redirect(link['short_url'], code=302)
        
    except Exception as e:
        current_app.logger.error(f"Start route error: {e}")
        return render_template('errors/500.html'), 500

@links_bp.route('/verify/<verify_token>')
def verify(verify_token):
    try:
        if not is_allowed_browser():
            return render_template('link/browser_restriction.html')
        
        fingerprint = generate_fingerprint()
        cookie_data = get_cookie_data()
        
        current_ip = get_client_ip()
        
        referer = request.headers.get('Referer', '')
        
        link = db.links.find_one({'verify_token': verify_token})
        
        if not link:
            return render_template('errors/404.html',
                error_title="Link Not Found",
                error_message='This link does not exist or has expired.')
        
        if not link.get('start_accessed', False):
            return render_template('errors/error.html',
                error_title="Nice Try Diddy! 🤡",
                error_message='Caught you red-handed trying to sneak in!')
        
        if link.get('is_bypassed', False):
            roast_titles = ['Nice Try Diddy! 🤡', 'Caught Lacking! 📸', 'You Thought! 💀', 'Not Today Fam! 🚫', 'L + Ratio 😂']
            stored_message = link.get('bypass_message', 'This link has been blocked. Better luck next time!')
            return render_template('errors/error.html',
                error_title=random.choice(roast_titles),
                error_message=stored_message)
        
        if link.get('status') == 'used':
            return render_template('errors/error.html',
                error_title="Link Already Used",
                error_message='This link has already been used.')
        
        user = get_user_by_username(link['username'])
        if not user:
            return render_template('errors/error.html',
                error_title="System Error",
                error_message="The owner of this link no longer exists.")
                
        user_settings = user.get('settings', {})
        encrypted_token = link['encrypted_token']
        
        if user_settings.get('require_same_ip', False):
            stored_ip = link.get('visitor_ip', '')
            if stored_ip and current_ip != stored_ip:
                if user_settings.get('block_after_bypass', True):
                    mark_link_bypassed(encrypted_token, 'ip_change', 'IP change detected!')
                return render_template('errors/error.html',
                    error_title="VPN Andy Detected! 🕵️",
                    error_message='Switching IPs like you switching personalities?')
        
        if user_settings.get('check_shortener_referer', True):
            configured_domain = user.get('shortener_domain', '').lower()
            referer_domain = urlparse(referer).netloc.lower() if referer else ''
            
            if configured_domain and referer:
                domain_parts = configured_domain.replace('api.', '').replace('www.', '').split('.')
                core_domain = domain_parts[0] if domain_parts else configured_domain
                if core_domain and referer_domain and core_domain not in referer_domain:
                    if user_settings.get('block_after_bypass', True):
                        mark_link_bypassed(encrypted_token, 'referer_bypass', 'Referer mismatch detected!')
                    return render_template('errors/error.html',
                        error_title="Caught Lacking! 📸",
                        error_message='LMAOOO you really thought you could skip the ads?')
        
        update_link_fingerprint(
            encrypted_token, 
            {
                'final_fingerprint': fingerprint,
                'final_cookies': cookie_data,
                'verify_ip': current_ip,
                'verify_referer': referer
            }
        )
        
        return render_template('link/verify.html',
            site_key=user['recaptcha_site_key'],
            encrypted_token=encrypted_token,
            verify_token=verify_token)
        
    except Exception as e:
        current_app.logger.error(f"Verify route error: {e}")
        return render_template('errors/500.html'), 500

@links_bp.route('/verify-start-captcha', methods=['POST'])
def verify_start_captcha():
    try:
        # ── Request validation ──
        if not request.is_json:
            return jsonify({'status': 'error', 'message': 'Invalid request format'}), 400
        
        data = request.get_json()
        encrypted_token = data.get('token')
        recaptcha_response = data.get('recaptcha')
        
        if not encrypted_token or not recaptcha_response:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        link = get_link_by_token(encrypted_token)
        if not link:
            return jsonify({'status': 'error', 'message': 'Link not found'}), 404
        
        user = get_user_by_username(link['username'])
        if not user:
            return jsonify({'status': 'error', 'message': 'System error'}), 404
        
        # Verify reCAPTCHA
        payload = {'secret': user['recaptcha_secret_key'], 'response': recaptcha_response}
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload, timeout=10)
        if not response.json().get('success', False):
            return jsonify({'status': 'error', 'message': 'reCAPTCHA verification failed'}), 400
        
        fingerprint = generate_fingerprint()
        cookie_data = get_cookie_data()
        
        update_link_fingerprint(
            encrypted_token, 
            {
                'initial_fingerprint': fingerprint,
                'initial_cookies': cookie_data,
                'verification_start_time': datetime.utcnow(),
                'start_accessed': True
            }
        )
        
        # Return opaque redirect token — short_url never touches the network tab
        redirect_token = _create_redirect_token(link['short_url'])
        return jsonify({'status': 'success', 'r': redirect_token})
    except Exception as e:
        current_app.logger.error(f"Verify-start-captcha error: {e}")
        return jsonify({'status': 'error', 'message': 'Verification failed'}), 500

@links_bp.route('/verify-captcha', methods=['POST'])
def verify_captcha():
    try:
        # ── Request validation ──
        if not request.is_json:
            return jsonify({'status': 'error', 'message': 'Invalid request format'}), 400
        
        data = request.get_json()
        encrypted_token = data.get('token')
        recaptcha_response = data.get('recaptcha')
        
        if not encrypted_token:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
        
        link = get_link_by_token(encrypted_token)
        if not link:
            return jsonify({'status': 'error', 'message': 'Link not found'}), 404
        
        user = get_user_by_username(link['username'])
        if not user:
            return jsonify({'status': 'error', 'message': 'System error'}), 404
                
        user_settings = user.get('settings', {})
        
        if user_settings.get('recaptcha_on_verify', True):
            if not recaptcha_response:
                return jsonify({'status': 'error', 'message': 'reCAPTCHA is required'}), 400
            payload = {'secret': user['recaptcha_secret_key'], 'response': recaptcha_response}
            response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload, timeout=10)
            if not response.json().get('success', False):
                return jsonify({'status': 'error', 'message': 'reCAPTCHA verification failed'}), 400
        
        if user_settings.get('enable_verification_time_check', True):
            min_time = user_settings.get('verification_time_seconds', 0)
            if min_time > 0:
                start_time = link.get('verification_start_time')
                if start_time and (datetime.utcnow() - start_time).total_seconds() < min_time:
                    mark_link_bypassed(encrypted_token, 'speedrun', 'Speedrunning detected!')
                    return jsonify({'status': 'error', 'message': 'Verification failed'}), 403
        
        if user_settings.get('enable_fingerprint_check', True):
            if link.get('initial_fingerprint') != link.get('final_fingerprint'):
                mark_link_bypassed(encrypted_token, 'device_swap', 'Device swap detected!')
                return jsonify({'status': 'error', 'message': 'Verification failed'}), 403
        
        if user_settings.get('enable_cookie_check', True):
            initial = link.get('initial_cookies', {})
            final = link.get('final_cookies', {})
            if initial.get('has_cookies') != final.get('has_cookies'):
                mark_link_bypassed(encrypted_token, 'cookie_mismatch', 'Cookie mismatch detected!')
                return jsonify({'status': 'error', 'message': 'Verification failed'}), 403
        
        db.links.update_one({'encrypted_token': encrypted_token}, {'$set': {'verification_end_time': datetime.utcnow()}})
        
        if user_settings.get('block_after_verify_complete', True):
            mark_link_used(encrypted_token)
        else:
            db.links.update_one({'encrypted_token': encrypted_token}, {'$inc': {'usage_count': 1}})
        
        # ── CRITICAL: Never expose original_url in JSON response ──
        # Instead, create a one-time opaque redirect token
        redirect_token = _create_redirect_token(link['original_url'])
        return jsonify({'status': 'success', 'r': redirect_token})
    except Exception as e:
        current_app.logger.error(f"Verify-captcha error: {e}")
        return jsonify({'status': 'error', 'message': 'Verification failed'}), 500

@links_bp.route('/r/<token>')
def secure_redirect(token):
    """One-time opaque redirect. URL is never visible in network tab."""
    url = _consume_redirect_token(token)
    if not url:
        return render_template('errors/error.html',
            error_title="Redirect Expired",
            error_message='This redirect token has expired or already been used. Please regenerate the link.')
    return redirect(url, code=302)

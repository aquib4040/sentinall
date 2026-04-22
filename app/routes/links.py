from flask import Blueprint, render_template, request, redirect, jsonify, current_app
from datetime import datetime, timedelta
import random
import requests
from urllib.parse import urlparse
from ..models.link import get_link_by_token, get_link_by_verify_token, update_link_fingerprint, mark_link_bypassed, mark_link_used
from ..models.user import get_user_by_username
from ..utils.security import generate_fingerprint, get_cookie_data, is_allowed_browser
from ..models.database import db

links_bp = Blueprint('links', __name__)

@links_bp.route('/start/<encrypted_token>')
def start(encrypted_token):
    try:
        if not is_allowed_browser():
            return render_template('link/browser_restriction.html')
        
        fingerprint = generate_fingerprint()
        cookie_data = get_cookie_data()
        
        visitor_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if visitor_ip and ',' in visitor_ip:
            visitor_ip = visitor_ip.split(',')[0].strip()
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
        return render_template('errors/500.html',
            error_title="Error",
            error_message=f"An error occurred: {str(e)}")

@links_bp.route('/verify/<verify_token>')
def verify(verify_token):
    try:
        if not is_allowed_browser():
            return render_template('link/browser_restriction.html')
        
        fingerprint = generate_fingerprint()
        cookie_data = get_cookie_data()
        
        current_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if current_ip and ',' in current_ip:
            current_ip = current_ip.split(',')[0].strip()
        
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
        return render_template('errors/500.html',
            error_title="Error",
            error_message=f"An error occurred: {str(e)}")

@links_bp.route('/verify-start-captcha', methods=['POST'])
def verify_start_captcha():
    try:
        data = request.get_json()
        encrypted_token = data.get('token')
        recaptcha_response = data.get('recaptcha')
        
        link = get_link_by_token(encrypted_token)
        if not link:
            return jsonify({'status': 'error', 'message': 'Link not found'}), 404
        
        user = get_user_by_username(link['username'])
        
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
        
        return jsonify({'status': 'success', 'redirect_url': link['short_url']})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@links_bp.route('/verify-captcha', methods=['POST'])
def verify_captcha():
    try:
        data = request.get_json()
        encrypted_token = data.get('token')
        recaptcha_response = data.get('recaptcha')
        
        link = get_link_by_token(encrypted_token)
        if not link:
            return jsonify({'status': 'error', 'message': 'Link not found'}), 404
        
        user = get_user_by_username(link['username'])
        user_settings = user.get('settings', {})
        
        if user_settings.get('recaptcha_on_verify', True):
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
                    return jsonify({'status': 'error', 'message': 'Too fast!', 'bypass_detected': True}), 403
        
        if user_settings.get('enable_fingerprint_check', True):
            if link.get('initial_fingerprint') != link.get('final_fingerprint'):
                mark_link_bypassed(encrypted_token, 'device_swap', 'Device swap detected!')
                return jsonify({'status': 'error', 'message': 'Device mismatch!', 'bypass_detected': True}), 403
        
        if user_settings.get('enable_cookie_check', True):
            if link.get('initial_cookies', {}).get('has_cookies') != link.get('final_cookies', {}).get('has_cookies'):
                mark_link_bypassed(encrypted_token, 'cookie_mismatch', 'Cookie mismatch detected!')
                return jsonify({'status': 'error', 'message': 'Cookie mismatch!', 'bypass_detected': True}), 403
        
        db.links.update_one({'encrypted_token': encrypted_token}, {'$set': {'verification_end_time': datetime.utcnow()}})
        
        if user_settings.get('block_after_verify_complete', True):
            mark_link_used(encrypted_token)
        else:
            db.links.update_one({'encrypted_token': encrypted_token}, {'$inc': {'usage_count': 1}})
        
        return jsonify({'status': 'success', 'redirect_url': link['original_url']})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

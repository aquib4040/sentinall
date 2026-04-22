import hashlib
import json
import secrets
from flask import request, current_app
from cryptography.fernet import Fernet

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

def is_allowed_browser():
    """Check if the browser is Chrome or Edge"""
    user_agent = request.headers.get('User-Agent', '').lower()
    is_chrome = 'chrome' in user_agent and 'edg' not in user_agent
    is_edge = 'edg' in user_agent
    return is_chrome or is_edge

def get_cipher():
    key = current_app.config['ENCRYPTION_KEY']
    if not key:
        raise ValueError("ENCRYPTION_KEY not set in configuration")
    return Fernet(key.encode())

def generate_encrypted_token():
    cipher = get_cipher()
    random_string = secrets.token_urlsafe(32)
    return cipher.encrypt(random_string.encode()).decode()

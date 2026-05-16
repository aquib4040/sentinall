import hashlib
import json
import secrets
from flask import request, current_app
from cryptography.fernet import Fernet

def generate_fingerprint():
    """Generate a robust browser fingerprint hash from request headers.
    
    Collects multiple browser signals to create a unique device identifier.
    More signals = harder to spoof across start/verify steps.
    """
    fingerprint_data = {
        # Core browser identity
        'user_agent': request.headers.get('User-Agent', ''),
        'accept_language': request.headers.get('Accept-Language', ''),
        'accept_encoding': request.headers.get('Accept-Encoding', ''),
        'accept': request.headers.get('Accept', ''),
        
        # Client hints (Chromium-based browsers)
        'platform': request.headers.get('Sec-Ch-Ua-Platform', ''),
        'ua_full': request.headers.get('Sec-Ch-Ua', ''),
        'ua_mobile': request.headers.get('Sec-Ch-Ua-Mobile', ''),
        'ua_arch': request.headers.get('Sec-Ch-Ua-Arch', ''),
        'ua_bitness': request.headers.get('Sec-Ch-Ua-Bitness', ''),
        'ua_model': request.headers.get('Sec-Ch-Ua-Model', ''),
        'ua_platform_version': request.headers.get('Sec-Ch-Ua-Platform-Version', ''),
        
        # Connection hints
        'connection': request.headers.get('Connection', ''),
        'dnt': request.headers.get('DNT', ''),
        
        # Fetch metadata (anti-bypass: detects direct navigation vs redirect)
        'sec_fetch_dest': request.headers.get('Sec-Fetch-Dest', ''),
        'sec_fetch_mode': request.headers.get('Sec-Fetch-Mode', ''),
        'sec_fetch_site': request.headers.get('Sec-Fetch-Site', ''),
    }
    fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()

def get_cookie_data():
    """Extract cookie metadata from request for consistency verification.
    
    Stores cookie count and session cookie presence rather than raw values
    to avoid false positives from rotating session tokens.
    """
    cookies = dict(request.cookies)
    return {
        'cookie_count': len(cookies),
        'has_cookies': len(cookies) > 0,
        'has_session': any(k.startswith('urlshortener_') or k.startswith('__') for k in cookies.keys()),
    }

def is_allowed_browser():
    """Check if the browser is Chrome or Edge (Chromium-based).
    
    Validates against known Chromium user-agent patterns while
    excluding bots, headless browsers, and non-Chromium engines.
    """
    user_agent = request.headers.get('User-Agent', '').lower()
    
    # Block empty/missing user agents (bots, curl, etc.)
    if not user_agent or len(user_agent) < 20:
        return False
    
    # Block known automation tools and headless browsers
    blocked_indicators = [
        'headlesschrome', 'phantomjs', 'selenium', 'webdriver',
        'python-requests', 'curl/', 'wget/', 'httpie/', 'postman',
        'bot', 'crawl', 'spider', 'scrape'
    ]
    if any(indicator in user_agent for indicator in blocked_indicators):
        return False
    
    is_chrome = 'chrome' in user_agent and 'edg' not in user_agent
    is_edge = 'edg' in user_agent
    return is_chrome or is_edge

def get_cipher():
    """Get Fernet cipher for token encryption/decryption."""
    key = current_app.config['ENCRYPTION_KEY']
    if not key:
        raise ValueError("ENCRYPTION_KEY not set in configuration")
    return Fernet(key.encode())

def generate_encrypted_token():
    """Generate a unique encrypted token for link identification."""
    cipher = get_cipher()
    random_string = secrets.token_urlsafe(32)
    return cipher.encrypt(random_string.encode()).decode()

def get_client_ip():
    """Extract the real client IP, handling proxies and Cloudflare.
    
    Priority: CF-Connecting-IP > X-Real-IP > X-Forwarded-For > remote_addr
    """
    # Cloudflare
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip.strip()
    
    # Nginx/reverse proxy
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip.strip()
    
    # Standard proxy header (take first IP = original client)
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    
    return request.remote_addr or '0.0.0.0'

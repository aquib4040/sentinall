import os
import secrets
from cryptography.fernet import Fernet
from datetime import timedelta

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_NAME = 'urlshortener_session'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)

    # Database settings
    MONGODB_URI = os.environ.get('MONGODB_URI')
    MONGODB_DB_NAME = os.environ.get('MONGODB_DB_NAME')

    # Admin settings
    OWNER_EMAIL = os.environ.get('OWNER_EMAIL')
    OWNER_PASSWORD = os.environ.get('OWNER_PASSWORD')
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')

    @staticmethod
    def init_app(app):
        pass

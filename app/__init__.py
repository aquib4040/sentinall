from flask import Flask, session, request, abort, render_template
from .config import Config
from .models.database import db
import secrets

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)

    # ── Security Headers Middleware ──
    @app.after_request
    def set_security_headers(response):
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        # XSS protection (legacy browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # Prevent referer leakage of sensitive URLs
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Disable caching on authenticated pages
        if session.get('logged_in') or session.get('owner_logged_in'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
        # Permissions policy — restrict dangerous browser APIs
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()'
        return response

    # ── CSRF Protection for POST forms ──
    @app.before_request
    def csrf_protect():
        if request.method == 'POST':
            # Skip CSRF for JSON API endpoints (they use API keys)
            if request.is_json:
                return
            # Skip CSRF for external API endpoints
            if request.path.startswith('/api'):
                return
            # Validate CSRF token for form submissions
            token = session.get('csrf_token')
            form_token = request.form.get('csrf_token')
            if not token or token != form_token:
                abort(403)

    # ── Generate CSRF token for templates ──
    @app.context_processor
    def inject_csrf():
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return {'csrf_token': session['csrf_token']}

    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.admin import admin_bp
    from .routes.api import api_bp
    from .routes.links import links_bp
    from .routes.main import main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(links_bp)
    app.register_blueprint(main_bp)

    # ── Error Handlers ──
    @app.errorhandler(403)
    def forbidden(e):
        return '<h1>403 Forbidden</h1><p>Request validation failed.</p>', 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    return app

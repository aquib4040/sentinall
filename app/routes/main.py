from flask import Blueprint, redirect, url_for, session, render_template

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    if session.get('owner_logged_in'):
        return redirect(url_for('admin.index'))
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
    return redirect(url_for('auth.login'))

@main_bp.app_errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@main_bp.app_errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

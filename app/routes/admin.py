from flask import Blueprint, render_template, request, jsonify, session, current_app
from ..models.user import get_all_users, get_user_by_username, toggle_user_status, delete_user
from ..models.stats import get_user_stats, get_user_earnings, get_database_stats
from ..models.link import get_links_by_username
from ..utils.decorators import owner_required

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/owner-dashboard')
@owner_required
def index():
    try:
        all_users = get_all_users()
        total_stats = get_database_stats()
        
        # Calculate total earnings from all users
        platform_earnings = 0
        for user in all_users:
            earnings = get_user_earnings(user['username'])
            platform_earnings += earnings.get('lifetime', {}).get('total_earnings', 0)
        
        total_stats['total_earnings'] = platform_earnings
        
        return render_template('admin/index.html',
            users=all_users,
            stats=total_stats)
    except Exception as e:
        return render_template('admin/index.html',
            error=f'Error loading dashboard: {str(e)}',
            users=[],
            stats={'total_users': 0, 'active_users': 0, 'total_links': 0, 'total_earnings': 0})

@admin_bp.route('/owner/user/<username>')
@owner_required
def user_details(username):
    try:
        user = get_user_by_username(username)
        if not user:
            return render_template('errors/404.html',
                error_title='User Not Found',
                error_message='This user does not exist.')
        
        user_links = get_links_by_username(username, limit=100)
        earnings = get_user_earnings(username)
        stats = get_user_stats(username)
        
        return render_template('admin/user_details.html',
            user=user,
            stats=stats,
            earnings=earnings,
            user_links=user_links,
            app_url=request.url_root.rstrip('/'))
    except Exception as e:
        return render_template('errors/500.html',
            error_title='Error',
            error_message=f'Error loading user details: {str(e)}')

@admin_bp.route('/owner/user/<username>/disable', methods=['POST'])
@owner_required
def disable_user_route(username):
    try:
        user = get_user_by_username(username)
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
            
        current_status = user.get('status', 'active')
        target_status = 'disabled' if current_status == 'active' else 'active'
        
        toggle_user_status(username, target_status)
        return jsonify({
            'status': 'success', 
            'message': f'User {username} is now {target_status}',
            'new_status': target_status
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@admin_bp.route('/owner/user/<username>/delete', methods=['POST'])
@owner_required
def delete_user_route(username):
    try:
        delete_user(username)
        return jsonify({'status': 'success', 'message': f'User {username} and all associated links have been deleted'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

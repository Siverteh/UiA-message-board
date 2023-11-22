from flask import Blueprint, render_template

error_bp = Blueprint('error', __name__)

#Error route to handle 404 not found.
@error_bp.app_errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

#Error route to handle 429 too many requests.
@error_bp.app_errorhandler(429)
def ratelimit_error(error):
    return render_template('errors/429.html'), 429

#Error route to handle 403 forbidden template.
@error_bp.app_errorhandler(403)
def forbidden_template_error(error):
    return render_template('errors/403.html'), 403

#Error route to handle 500 internal server.
@error_bp.app_errorhandler(500)
def internal_server_error(error):
    return render_template('errors/500.html'), 500
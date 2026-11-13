"""CyberGuard AI - the starting point of the application.

Run it with:  python app.py
"""
from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFError, CSRFProtect

from config import PLACEHOLDER_KEYS, Config
from database.db import db
from routes.admin_routes import admin_bp
from routes.ai_routes import ai_bp
from routes.auth_routes import auth_bp
from routes.dashboard_routes import dashboard_bp
from routes.scanner_routes import scanner_bp

csrf = CSRFProtect()


def create_app(test_config=None):
    """Build and return the Flask app. Tests pass test_config to change settings."""
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    if app.config.get("SECRET_KEY", "") in PLACEHOLDER_KEYS:
        raise RuntimeError(
            "SECRET_KEY is missing or still the example value. "
            "Open your .env file and set SECRET_KEY to a long random text. "
            'Create one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )

    db.init_app(app)
    csrf.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(admin_bp)

    register_error_handlers(app)

    @app.after_request
    def stop_page_caching(response):
        # The Back button must not show private pages after logout
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    with app.app_context():
        import models  # noqa: F401  (lets SQLAlchemy see our tables)
        db.create_all()  # creates cyberguard.db and the tables if they do not exist

    return app


def register_error_handlers(app):
    """Friendly error pages instead of raw technical errors."""

    def show_error(code, title, message):
        return render_template("error.html", code=code, title=title, message=message), code

    @app.errorhandler(CSRFError)
    def csrf_error(error):
        return show_error(
            400, "Form expired",
            "Your form expired or could not be verified. Go back, refresh the page and try again.",
        )

    @app.errorhandler(403)
    def forbidden(error):
        return show_error(403, "Access denied", "You do not have permission to open this page.")

    @app.errorhandler(404)
    def not_found(error):
        return show_error(404, "Page not found", "The page you are looking for does not exist.")

    @app.errorhandler(500)
    def server_error(error):
        db.session.rollback()
        return show_error(500, "Something went wrong", "An unexpected error happened. Please try again.")


if __name__ == "__main__":
    # 127.0.0.1 means only your own computer can open the site
    create_app().run(host="127.0.0.1", port=5000)
"""A small admin page. The full admin panel is built in Phase 18."""
from flask import Blueprint, render_template

from models.user import User
from utils.decorators import admin_required

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@admin_required
def dashboard():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/dashboard.html", users=users)
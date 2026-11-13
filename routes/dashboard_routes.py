"""The home redirect and the main dashboard page."""
from flask import Blueprint, g, redirect, render_template, url_for

from services.dashboard_service import get_dashboard_data
from utils.decorators import login_required
from utils.helpers import local_time

dashboard_bp = Blueprint("dashboard", __name__)

# Lets every template write:  {{ some_time|local_time }}
dashboard_bp.add_app_template_filter(local_time, "local_time")


@dashboard_bp.route("/")
def home():
    if g.user:
        return redirect(url_for("dashboard.index"))
    return redirect(url_for("auth.login"))


@dashboard_bp.route("/dashboard")
@login_required
def index():
    data = get_dashboard_data(g.user.id)

    # Only the numbers the charts need. The template puts them in the page as JSON.
    chart_data = {
        "activity": data["activity"],
        "distribution": {
            "labels": [level["name"] for level in data["levels"]],
            "counts": [level["count"] for level in data["levels"]],
        },
    }
    return render_template("dashboard/index.html", data=data, chart_data=chart_data)
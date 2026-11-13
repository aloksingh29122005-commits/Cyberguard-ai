"""AI pages. Phase 8 has the connection status page; Phase 9 adds the assistant here."""
from flask import Blueprint, flash, g, redirect, render_template, url_for

from services.ai_service import get_ai_service
from utils.decorators import admin_required, login_required

ai_bp = Blueprint("ai", __name__, url_prefix="/ai")


@ai_bp.route("/status")
@login_required
def status():
    return render_template("ai/status.html", info=get_ai_service().describe())


@ai_bp.route("/test", methods=["POST"])
@admin_required
def test_connection():
    """Sends one fixed, harmless question to check the settings. Only admins may do this (it can cost money)."""
    result = get_ai_service().test_connection(g.user.id)

    if result.source == "ai":
        flash("The AI answered: " + result.text[:300], "success")
    else:
        message = "The AI did not answer. " + result.reason
        if result.detail:
            message += " The service said: " + result.detail
        flash(message[:500], "warning")

    # Redirect, so refreshing the page does not send another question
    return redirect(url_for("ai.status"))
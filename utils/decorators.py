"""Decorators that protect pages. Put them just under @route."""
from functools import wraps

from flask import abort, flash, g, redirect, url_for


def login_required(view):
    """Only logged-in users may open the page. Others are sent to the login page."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped_view


def admin_required(view):
    """Only admins may open the page. Logged-in normal users get a 403 (access denied)."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))
        if not g.user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped_view
"""Register, log in and log out."""
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy.exc import IntegrityError

from database.db import db
from models.user import User
from utils.validators import validate_registration

auth_bp = Blueprint("auth", __name__)


@auth_bp.before_app_request
def load_logged_in_user():
    """Runs before every request: finds out who is logged in (if anyone)."""
    g.user = None
    if request.endpoint == "static":
        return

    user_id = session.get("user_id")
    if user_id is None:
        return

    user = db.session.get(User, user_id)
    if user is None or not user.is_active:
        session.clear()  # the account was deleted or disabled
        return

    g.user = user


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard.index"))

    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    errors = validate_registration(username, email, password, confirm_password)

    if not errors:
        if User.query.filter(db.func.lower(User.username) == username.lower()).first():
            errors.append("That username is already taken.")
        if User.query.filter_by(email=email).first():
            errors.append("An account with that email already exists.")

    if errors:
        for message in errors:
            flash(message, "danger")
        return render_template("register.html", username=username, email=email)

    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:  # two people registered the same name at the same moment
        db.session.rollback()
        flash("That username or email is already registered.", "danger")
        return render_template("register.html", username=username, email=email)

    flash("Account created. Please log in.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard.index"))

    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    user = User.query.filter_by(email=email).first()

    # One message for both "no such email" and "wrong password"
    if user is None or not user.check_password(password):
        flash("Invalid email or password.", "danger")
        return render_template("login.html", email=email)

    if not user.is_active:
        flash("This account is disabled. Please contact an administrator.", "danger")
        return render_template("login.html", email=email)

    session.clear()  # start a fresh session
    session["user_id"] = user.id
    session.permanent = True
    flash(f"Welcome back, {user.username}.", "success")
    return redirect(url_for("dashboard.index"))


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
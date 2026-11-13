"""Tests for registration, login, logout, roles and CSRF protection."""
import re

from app import create_app
from database.db import db
from models.user import User
from tests.conftest import TEST_CONFIG

PASSWORD = "StrongPass123"


def register(client, username="tester", email="tester@example.com", password=PASSWORD, confirm=None):
    return client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password if confirm is None else confirm,
        },
        follow_redirects=True,
    )


def login(client, email="tester@example.com", password=PASSWORD):
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=True)


def make_user(app, username, email, role="user", is_active=True):
    """Put a user straight into the database (used for admin and disabled users)."""
    with app.app_context():
        user = User(username=username, email=email, role=role, is_active=is_active)
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()


# ---------- Registration ----------

def test_register_saves_hashed_password(app, client):
    response = register(client)
    assert b"Account created" in response.data
    with app.app_context():
        user = User.query.filter_by(email="tester@example.com").first()
        assert user is not None
        assert user.role == "user"
        assert user.password_hash != PASSWORD
        assert PASSWORD not in user.password_hash


def test_register_rejects_duplicate_email(app, client):
    register(client)
    response = register(client, username="another")
    assert b"already exists" in response.data
    with app.app_context():
        assert User.query.count() == 1


def test_register_rejects_short_password(app, client):
    response = register(client, password="Ab1")
    assert b"at least 8 characters" in response.data
    with app.app_context():
        assert User.query.count() == 0


def test_register_rejects_common_password(client):
    response = register(client, password="Password1")
    assert b"too common" in response.data


def test_register_rejects_mismatched_passwords(client):
    response = register(client, confirm="DifferentPass123")
    assert b"do not match" in response.data


# ---------- Login and logout ----------

def test_login_success_shows_dashboard(client):
    register(client)
    response = login(client)
    assert b"Welcome, tester" in response.data
    assert b"No scans yet" in response.data


def test_login_wrong_password_gives_generic_error(client):
    register(client)
    response = login(client, password="WrongPass123")
    assert b"Invalid email or password" in response.data


def test_login_unknown_email_gives_same_error(client):
    response = login(client, email="nobody@example.com")
    assert b"Invalid email or password" in response.data


def test_disabled_user_cannot_log_in(app, client):
    make_user(app, "blocked", "blocked@example.com", is_active=False)
    response = login(client, email="blocked@example.com")
    assert b"disabled" in response.data


def test_logout_ends_the_session(client):
    register(client)
    login(client)
    client.post("/logout")
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


# ---------- Protected pages and roles ----------

def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_admin_page_requires_login(client):
    response = client.get("/admin/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_normal_user_cannot_open_admin_page(client):
    register(client)
    login(client)
    assert client.get("/admin/").status_code == 403


def test_admin_can_open_admin_page(app, client):
    make_user(app, "boss", "boss@example.com", role="admin")
    login(client, email="boss@example.com")
    response = client.get("/admin/")
    assert response.status_code == 200
    assert b"Registered users" in response.data


# ---------- CSRF protection ----------

def test_post_without_csrf_token_is_rejected():
    config = dict(TEST_CONFIG, WTF_CSRF_ENABLED=True)
    client = create_app(config).test_client()
    response = client.post("/register", data={
        "username": "tester", "email": "tester@example.com",
        "password": PASSWORD, "confirm_password": PASSWORD,
    })
    assert response.status_code == 400


def test_post_with_csrf_token_is_accepted():
    config = dict(TEST_CONFIG, WTF_CSRF_ENABLED=True)
    client = create_app(config).test_client()
    page = client.get("/register").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    response = client.post("/register", data={
        "csrf_token": token, "username": "tester", "email": "tester@example.com",
        "password": PASSWORD, "confirm_password": PASSWORD,
    })
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
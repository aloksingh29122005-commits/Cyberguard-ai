"""Tests for the password check pages. The most important tests prove the password is never kept."""
import logging

from database.db import db
from models.alert import Alert
from models.scan import Scan
from models.user import User
from services.password_analyzer import TARGET_LABEL

LOGIN_PASSWORD = "StrongPass123"  # the password of the CyberGuard account, not the one being checked

WEAK = "password123"
MODERATE = "Tiger7Blue"
STRONG = "lantern-river-mango-quiet-47"
CANDIDATE = "Zx9-Unique-Candidate-7731!"


def make_user(app, username="owner", email="owner@example.com"):
    with app.app_context():
        user = User(username=username, email=email)
        user.set_password(LOGIN_PASSWORD)
        db.session.add(user)
        db.session.commit()
        return user.id


def log_in(client, email="owner@example.com"):
    return client.post("/login", data={"email": email, "password": LOGIN_PASSWORD}, follow_redirects=True)


def check(client, password, follow=True):
    return client.post("/scan/password", data={"password": password}, follow_redirects=follow)


def everything_saved():
    """All the text saved in the database (users, scans and alerts) as one string."""
    parts = []
    for model in (User, Scan, Alert):
        for row in model.query.all():
            parts.append(str({column.name: getattr(row, column.name) for column in model.__table__.columns}))
    return "\n".join(parts)


# ---------- Access ----------

def test_password_pages_need_login(client):
    response = client.get("/scan/password")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_password_page_opens_and_sidebar_links_to_it(app, client):
    make_user(app)
    log_in(client)
    page = client.get("/scan/password").get_data(as_text=True)
    assert "Check a password" in page
    assert "No password checks yet" in page
    assert 'type="password"' in page
    assert 'name="password"' in page
    assert 'autocomplete="off"' in page
    assert 'href="/scan/password"' in client.get("/dashboard").get_data(as_text=True)


def test_the_example_buttons_are_on_the_page(app, client):
    make_user(app)
    log_in(client)
    page = client.get("/scan/password").get_data(as_text=True)
    for example in (WEAK, MODERATE, STRONG):
        assert f'data-example="{example}"' in page


# ---------- Checking ----------

def test_weak_password_is_saved_with_an_alert(app, client):
    make_user(app)
    log_in(client)
    page = check(client, WEAK).get_data(as_text=True)

    assert "Password checked" in page
    assert "Password strength: <strong>Weak</strong>" in page
    assert "Weaknesses found" in page
    assert "Check another password" in page
    assert "The password itself was never saved." in page
    assert "Link details" not in page

    with app.app_context():
        saved = Scan.query.one()
        assert saved.scan_type == "password"
        assert saved.target == TARGET_LABEL
        assert saved.risk_score == 100
        assert saved.risk_level == "Critical"
        assert saved.is_demo is False

        alert = Alert.query.one()
        assert alert.severity == "Critical"
        assert alert.alert_type == "Weak password"
        assert alert.source == "Password analyzer"
        assert alert.status == "Open"
        assert WEAK not in alert.description


def test_strong_password_raises_no_alert_and_lists_the_good_points(app, client):
    make_user(app)
    log_in(client)
    page = check(client, STRONG).get_data(as_text=True)

    assert "Password strength: <strong>Strong</strong>" in page
    assert "No weaknesses found" in page
    assert "What is good" in page
    assert "Not one of the most common passwords" in page
    with app.app_context():
        assert Scan.query.one().risk_score == 0
        assert Alert.query.count() == 0


def test_moderate_password_raises_no_alert(app, client):
    make_user(app)
    log_in(client)
    page = check(client, MODERATE).get_data(as_text=True)
    assert "Password strength: <strong>Moderate</strong>" in page
    with app.app_context():
        assert Scan.query.one().risk_score == 30
        assert Alert.query.count() == 0


def test_posting_redirects_to_the_result_page(app, client):
    make_user(app)
    log_in(client)
    response = check(client, MODERATE, follow=False)
    assert response.status_code == 302
    assert "/scan/" in response.headers["Location"]


def test_the_username_inside_a_password_is_found(app, client):
    make_user(app)
    log_in(client)
    page = check(client, "Owner-Lantern-River-9").get_data(as_text=True)
    assert "Contains part of your username or email" in page
    with app.app_context():
        saved = Scan.query.one()
        assert "owner" not in (str(saved.indicators) + saved.explanation).lower()


# ---------- The password is never kept ----------

def test_the_password_is_never_saved_anywhere(app, client):
    make_user(app)
    log_in(client)
    check(client, CANDIDATE)
    with app.app_context():
        saved = everything_saved()
        assert TARGET_LABEL in saved  # the scan really is in the database, so the search below means something
        assert CANDIDATE not in saved
        assert CANDIDATE.lower() not in saved.lower()
        assert "Unique-Candidate" not in saved
        assert "7731" not in saved


def test_the_password_is_not_shown_in_any_page(app, client):
    make_user(app)
    log_in(client)
    result_page = check(client, CANDIDATE).get_data(as_text=True)
    for page in (result_page,
                 client.get("/scan/password").get_data(as_text=True),
                 client.get("/dashboard").get_data(as_text=True)):
        assert CANDIDATE not in page
        assert "Unique-Candidate" not in page


def test_the_password_is_not_written_to_the_log(app, client, caplog):
    make_user(app)
    log_in(client)
    caplog.set_level(logging.DEBUG)
    check(client, CANDIDATE)
    assert CANDIDATE not in caplog.text
    assert "Unique-Candidate" not in caplog.text


def test_the_password_is_not_put_in_the_address(app, client):
    make_user(app)
    log_in(client)
    response = check(client, CANDIDATE, follow=False)
    assert CANDIDATE not in response.headers["Location"]
    assert "Candidate" not in response.headers["Location"]


def test_a_password_in_the_address_bar_is_not_checked(app, client):
    make_user(app)
    log_in(client)
    client.get("/scan/password?password=" + CANDIDATE)
    with app.app_context():
        assert Scan.query.count() == 0


# ---------- Bad input ----------

def test_empty_password_shows_an_error_and_saves_nothing(app, client):
    make_user(app)
    log_in(client)
    page = check(client, "").get_data(as_text=True)
    assert "Please type a password to check." in page
    with app.app_context():
        assert Scan.query.count() == 0


def test_too_long_password_shows_an_error_and_is_not_repeated(app, client):
    make_user(app)
    log_in(client)
    too_long = "Zx9-" * 40
    page = check(client, too_long).get_data(as_text=True)
    assert "128" in page
    assert too_long not in page
    with app.app_context():
        assert Scan.query.count() == 0


# ---------- Lists and safety ----------

def test_recent_checks_show_the_result_but_never_the_password(app, client):
    make_user(app)
    log_in(client)
    check(client, CANDIDATE)
    page = client.get("/scan/password").get_data(as_text=True)
    assert "Weak" in page
    assert CANDIDATE not in page
    with app.app_context():
        assert f'href="/scan/{Scan.query.one().id}"' in page


def test_dashboard_shows_the_password_check_without_the_password(app, client):
    make_user(app)
    log_in(client)
    check(client, WEAK)
    page = client.get("/dashboard").get_data(as_text=True)
    assert TARGET_LABEL in page
    assert "Weak password" in page
    assert WEAK not in page


def test_a_password_result_can_only_be_opened_by_its_owner(app, client):
    make_user(app, "first", "first@example.com")
    make_user(app, "second", "second@example.com")

    log_in(client, "first@example.com")
    check(client, WEAK)
    with app.app_context():
        scan_id = Scan.query.one().id
    assert client.get(f"/scan/{scan_id}").status_code == 200

    other = app.test_client()
    log_in(other, "second@example.com")
    assert other.get(f"/scan/{scan_id}").status_code == 404
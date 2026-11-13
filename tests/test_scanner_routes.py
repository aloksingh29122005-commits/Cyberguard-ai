"""Tests for the URL scanner pages: scanning, saving, alerts and who may see what."""
from database.db import db
from models.alert import Alert
from models.scan import Scan
from models.user import User
from services.dashboard_service import get_dashboard_data

PASSWORD = "StrongPass123"
MEDIUM_LINK = "http://192.168.10.25/login/verify"
SAFE_LINK = "https://docs.python.org/3/"


def make_user(app, username="owner", email="owner@example.com"):
    with app.app_context():
        user = User(username=username, email=email)
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()
        return user.id


def log_in(client, email="owner@example.com"):
    return client.post("/login", data={"email": email, "password": PASSWORD}, follow_redirects=True)


def scan(client, url, follow=True):
    return client.post("/scan/url", data={"url": url}, follow_redirects=follow)


# ---------- Access ----------

def test_scanner_pages_need_login(client):
    for path in ("/scan/url", "/scan/1"):
        response = client.get(path)
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]


def test_scanner_page_opens_and_sidebar_links_to_it(app, client):
    make_user(app)
    log_in(client)
    page = client.get("/scan/url").get_data(as_text=True)
    assert "Check a link" in page
    assert "No link checks yet" in page
    assert 'href="/scan/url"' in client.get("/dashboard").get_data(as_text=True)


# ---------- Scanning ----------

def test_scan_is_saved_and_the_result_page_is_shown(app, client):
    make_user(app)
    log_in(client)
    page = scan(client, MEDIUM_LINK).get_data(as_text=True)

    assert "Scan result" in page
    assert "Warning signs found" in page
    assert "IP number" in page
    assert "What to do" in page

    with app.app_context():
        saved = Scan.query.one()
        assert saved.scan_type == "url"
        assert saved.target == MEDIUM_LINK
        assert saved.risk_score == 50
        assert saved.risk_level == "Medium"
        assert saved.is_demo is False
        assert {item["code"] for item in saved.indicators} == {"no_https", "ip_address", "keywords"}


def test_posting_redirects_to_the_result_page(app, client):
    make_user(app)
    log_in(client)
    response = scan(client, MEDIUM_LINK, follow=False)
    assert response.status_code == 302
    assert "/scan/" in response.headers["Location"]


def test_risky_scan_raises_an_alert(app, client):
    make_user(app)
    log_in(client)
    scan(client, MEDIUM_LINK)
    with app.app_context():
        alert = Alert.query.one()
        assert alert.severity == "Medium"
        assert alert.alert_type == "Suspicious URL"
        assert alert.source == "URL scanner"
        assert alert.status == "Open"
        assert alert.scan_id == Scan.query.one().id
        assert alert.is_demo is False


def test_safe_scan_raises_no_alert(app, client):
    make_user(app)
    log_in(client)
    page = scan(client, SAFE_LINK).get_data(as_text=True)
    assert "No warning signs found" in page
    with app.app_context():
        assert Scan.query.count() == 1
        assert Alert.query.count() == 0


def test_invalid_link_shows_an_error_and_saves_nothing(app, client):
    make_user(app)
    log_in(client)
    page = scan(client, "example.com").get_data(as_text=True)
    assert "Please start the link with http:// or https://" in page
    assert 'value="example.com"' in page  # what the user typed stays in the box
    with app.app_context():
        assert Scan.query.count() == 0
        assert Alert.query.count() == 0


def test_dashboard_numbers_include_the_new_scan(app, client):
    user_id = make_user(app)
    log_in(client)
    scan(client, MEDIUM_LINK)
    with app.app_context():
        data = get_dashboard_data(user_id)
        assert data["total_scans"] == 1
        assert data["total_threats"] == 1
        assert data["alert_counts"]["Medium"] == 1


def test_very_long_links_are_shortened_for_storage(app, client):
    make_user(app)
    log_in(client)
    response = scan(client, "https://example.com/" + "a" * 600)
    assert response.status_code == 200
    with app.app_context():
        saved = Scan.query.one()
        assert len(saved.target) == 500
        assert saved.target.endswith("...")
        assert "long_url" in {item["code"] for item in saved.indicators}


def test_recent_checks_are_listed_with_a_link_to_the_result(app, client):
    make_user(app)
    log_in(client)
    scan(client, MEDIUM_LINK)
    page = client.get("/scan/url").get_data(as_text=True)
    assert MEDIUM_LINK in page
    with app.app_context():
        assert f'href="/scan/{Scan.query.one().id}"' in page


# ---------- Safety ----------

def test_a_scan_can_only_be_opened_by_its_owner(app, client):
    make_user(app, "first", "first@example.com")
    make_user(app, "second", "second@example.com")

    log_in(client, "first@example.com")
    scan(client, MEDIUM_LINK)
    with app.app_context():
        scan_id = Scan.query.one().id
    assert client.get(f"/scan/{scan_id}").status_code == 200

    other = app.test_client()
    log_in(other, "second@example.com")
    assert other.get(f"/scan/{scan_id}").status_code == 404
    assert "Warning signs" not in other.get("/scan/url").get_data(as_text=True)


def test_the_scanned_text_is_shown_as_text_and_never_as_a_link_or_script(app, client):
    make_user(app)
    log_in(client)
    page = scan(client, "http://example.com/<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>alert(1)" not in page
    assert "&lt;script&gt;" in page
    assert 'href="http://example.com' not in page
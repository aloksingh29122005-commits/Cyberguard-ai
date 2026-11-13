"""Tests for the email analyzer pages: analyzing, saving, alerts, privacy and who may see what."""
import json

from database.db import db
from models.alert import Alert
from models.scan import Scan
from models.user import User

PASSWORD = "StrongPass123"

PHISHING_EMAIL = """From: "PayPal Support" <support@paypa1-secure.example>
Reply-To: helpdesk@gmail.com
Subject: URGENT: Your account will be suspended

Dear customer,

We noticed unusual activity on your account. You must verify your account within 24 hours or it will be suspended permanently.

Please confirm your password and OTP here: http://paypa1-secure.example/verify/login

Thank you,
Security Team"""

SAFE_EMAIL = """From: Priya Sharma <priya@example.org>
Subject: Notes from Friday's meeting

Hi team,

Here are the notes from Friday's meeting. The next meeting is on Tuesday at 10 am. Please send me any changes by Monday.

Thanks,
Priya"""


def make_user(app, username="owner", email="owner@example.com"):
    with app.app_context():
        user = User(username=username, email=email)
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()
        return user.id


def log_in(client, email="owner@example.com"):
    return client.post("/login", data={"email": email, "password": PASSWORD}, follow_redirects=True)


def analyze(client, text, follow=True):
    return client.post("/scan/email", data={"email_text": text}, follow_redirects=follow)


# ---------- Access ----------

def test_email_pages_need_login(client):
    response = client.get("/scan/email")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_email_page_opens_and_sidebar_links_to_it(app, client):
    make_user(app)
    log_in(client)
    page = client.get("/scan/email").get_data(as_text=True)
    assert "Check an email" in page
    assert "No email checks yet" in page
    assert 'href="/scan/email"' in client.get("/dashboard").get_data(as_text=True)


# ---------- Analyzing ----------

def test_phishing_email_is_saved_with_an_alert(app, client):
    make_user(app)
    log_in(client)
    page = analyze(client, PHISHING_EMAIL).get_data(as_text=True)

    assert "Scan result" in page
    assert "Email checked" in page
    assert "Warning signs found" in page
    assert "Analyze another email" in page
    assert "Link details" not in page  # that box is only for URL scans
    assert "paypa1-secure.example/verify/login (score 60, Medium)" in page  # the link that was found

    with app.app_context():
        saved = Scan.query.one()
        assert saved.scan_type == "email"
        assert saved.target == "Email: URGENT: Your account will be suspended (from support@paypa1-secure.example)"
        assert saved.risk_score == 100
        assert saved.risk_level == "Critical"
        assert saved.is_demo is False

        alert = Alert.query.one()
        assert alert.severity == "Critical"
        assert alert.alert_type == "Phishing email"
        assert alert.source == "Email analyzer"
        assert alert.status == "Open"
        assert alert.scan_id == saved.id


def test_normal_email_raises_no_alert(app, client):
    make_user(app)
    log_in(client)
    page = analyze(client, SAFE_EMAIL).get_data(as_text=True)
    assert "No warning signs found" in page
    with app.app_context():
        assert Scan.query.one().risk_score == 0
        assert Alert.query.count() == 0


def test_posting_redirects_to_the_result_page(app, client):
    make_user(app)
    log_in(client)
    response = analyze(client, SAFE_EMAIL, follow=False)
    assert response.status_code == 302
    assert "/scan/" in response.headers["Location"]


def test_the_email_text_itself_is_never_saved(app, client):
    make_user(app)
    log_in(client)
    secret_sentence = "my-private-sentence-4711"
    analyze(client, SAFE_EMAIL + "\n\n" + secret_sentence)
    with app.app_context():
        saved = Scan.query.one()
        everything = saved.target + saved.explanation + json.dumps(saved.indicators)
        assert secret_sentence not in everything
        assert "Here are the notes" not in everything


def test_too_short_text_shows_an_error_and_saves_nothing(app, client):
    make_user(app)
    log_in(client)
    page = analyze(client, "hi there").get_data(as_text=True)
    assert "too short to be a whole email" in page
    assert "hi there" in page  # what the user typed stays in the box
    with app.app_context():
        assert Scan.query.count() == 0


def test_dashboard_shows_the_email_scan(app, client):
    make_user(app)
    log_in(client)
    analyze(client, PHISHING_EMAIL)
    page = client.get("/dashboard").get_data(as_text=True)
    assert "URGENT: Your account will be suspended" in page
    assert "Phishing email" in page


def test_recent_email_checks_are_listed_with_a_link_to_the_result(app, client):
    make_user(app)
    log_in(client)
    analyze(client, SAFE_EMAIL)
    page = client.get("/scan/email").get_data(as_text=True)
    assert "Notes from Friday" in page
    with app.app_context():
        assert f'href="/scan/{Scan.query.one().id}"' in page
    # URL checks and email checks have separate lists
    assert "Notes from Friday" not in client.get("/scan/url").get_data(as_text=True)


# ---------- Safety ----------

def test_an_email_scan_can_only_be_opened_by_its_owner(app, client):
    make_user(app, "first", "first@example.com")
    make_user(app, "second", "second@example.com")

    log_in(client, "first@example.com")
    analyze(client, PHISHING_EMAIL)
    with app.app_context():
        scan_id = Scan.query.one().id
    assert client.get(f"/scan/{scan_id}").status_code == 200

    other = app.test_client()
    log_in(other, "second@example.com")
    assert other.get(f"/scan/{scan_id}").status_code == 404


def test_scary_text_in_the_subject_is_shown_as_text_never_as_script(app, client):
    make_user(app)
    log_in(client)
    text = "From: Priya <priya@example.org>\nSubject: <script>alert(1)</script> hello\n\nJust a normal note for you."
    page = analyze(client, text).get_data(as_text=True)
    assert "<script>alert(1)" not in page
    assert "&lt;script&gt;" in page


def test_the_example_emails_on_the_page_do_not_break_it(app, client):
    make_user(app)
    log_in(client)
    page = client.get("/scan/email").get_data(as_text=True)
    for example_id in ("example-safe", "example-medium", "example-high"):
        assert f'id="{example_id}"' in page
"""Tests for the AI connection page and the admin's test button. No internet is used."""
from unittest.mock import patch

import pytest

from app import create_app
from database.db import db
from models.user import User
from services import ai_service
from services.ai_service import TEST_QUESTION
from tests.conftest import TEST_CONFIG
from tests.test_ai_service import FakeResponse, anthropic_answer

PASSWORD = "StrongPass123"
KEY = "sk-test-SECRETKEY1234567890abcdefghij"

AI_ON = {"AI_PROVIDER": "anthropic", "AI_API_KEY": KEY, "AI_MODEL": "claude-test-model"}


@pytest.fixture(autouse=True)
def fresh_limiter():
    """Every test starts with an empty count of AI questions."""
    ai_service._shared_limiter.reset()
    yield


def make_app(**settings):
    """An app with the given AI settings (the normal `app` fixture has the AI switched off)."""
    return create_app(dict(TEST_CONFIG, **settings))


def make_user(app, username="owner", email="owner@example.com", role="user"):
    with app.app_context():
        user = User(username=username, email=email, role=role)
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()


def log_in(client, email="owner@example.com"):
    return client.post("/login", data={"email": email, "password": PASSWORD}, follow_redirects=True)


def status_page(app, role="user"):
    """Log in with the given role and return the text of the status page."""
    make_user(app, role=role)
    client = app.test_client()
    log_in(client)
    return client.get("/ai/status").get_data(as_text=True)


# ---------- Access ----------

def test_the_status_page_needs_login(client):
    response = client.get("/ai/status")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_the_sidebar_links_to_the_status_page(app, client):
    make_user(app)
    log_in(client)
    assert 'href="/ai/status"' in client.get("/dashboard").get_data(as_text=True)


# ---------- What people see ----------

def test_a_normal_user_sees_a_simple_status_when_the_ai_is_off(app):
    page = status_page(app)
    assert "AI connection" in page
    assert "The AI is switched off" in page
    assert "Provider" not in page
    assert "Send a test question" not in page


def test_a_normal_user_never_sees_technical_details(app):
    page = status_page(make_app(**AI_ON))
    assert "AI answers are available." in page
    assert "claude-test-model" not in page
    assert "api.anthropic.com" not in page
    assert KEY not in page
    assert "Send a test question" not in page


def test_a_normal_user_sees_a_simple_message_when_the_ai_is_not_ready(app):
    page = status_page(make_app(AI_PROVIDER="anthropic"))
    assert "Not ready" in page
    assert "Please ask the administrator." in page
    assert "AI_MODEL" not in page


def test_the_admin_sees_the_details_but_never_the_key(app):
    page = status_page(make_app(**AI_ON), role="admin")
    assert "Anthropic (Claude)" in page
    assert "claude-test-model" in page
    assert "api.anthropic.com" in page
    assert "Set (it is never shown)" in page
    assert "Send a test question" in page
    assert ' disabled>Send a test question' not in page
    assert KEY not in page
    assert "SECRETKEY" not in page


def test_the_admin_sees_what_is_missing_and_the_button_is_disabled(app):
    page = status_page(make_app(AI_PROVIDER="anthropic", AI_API_KEY=KEY), role="admin")
    assert "AI_MODEL is not set." in page
    assert ' disabled>Send a test question' in page


def test_the_page_says_what_is_sent_to_the_ai(app):
    page = status_page(app)
    assert "Passwords are never sent" in page
    assert "never the whole email or message" in page


# ---------- The test button ----------

def test_only_admins_can_use_the_test_button():
    app = make_app(**AI_ON)
    make_user(app)
    client = app.test_client()
    log_in(client)
    with patch("services.ai_service.requests.post", return_value=anthropic_answer()) as mock_post:
        response = client.post("/ai/test")
    assert response.status_code == 403
    mock_post.assert_not_called()


def test_the_test_button_shows_the_ai_answer():
    app = make_app(**AI_ON)
    make_user(app, role="admin")
    client = app.test_client()
    log_in(client)
    with patch("services.ai_service.requests.post", return_value=anthropic_answer("A trick to steal details.")) as mock_post:
        page = client.post("/ai/test", follow_redirects=True).get_data(as_text=True)

    assert "The AI answered: A trick to steal details." in page
    assert mock_post.call_count == 1
    assert mock_post.call_args.kwargs["json"]["messages"] == [{"role": "user", "content": TEST_QUESTION}]


def test_a_failed_test_shows_a_reason_and_never_the_key():
    app = make_app(**AI_ON)
    make_user(app, role="admin")
    client = app.test_client()
    log_in(client)
    refused = FakeResponse(401, {"error": {"message": f"Incorrect key {KEY}. Check your settings."}})
    with patch("services.ai_service.requests.post", return_value=refused):
        page = client.post("/ai/test", follow_redirects=True).get_data(as_text=True)

    assert "The AI did not answer." in page
    assert "did not accept the key" in page
    assert "The service said:" in page
    assert "Check your settings." in page
    assert KEY not in page
    assert "SECRETKEY" not in page


def test_the_test_button_with_the_ai_off_makes_no_call(app, client):
    make_user(app, role="admin")
    log_in(client)
    with patch("services.ai_service.requests.post", return_value=anthropic_answer()) as mock_post:
        page = client.post("/ai/test", follow_redirects=True).get_data(as_text=True)
    assert "The AI did not answer." in page
    assert "AI is switched off" in page
    mock_post.assert_not_called()


def test_refreshing_after_the_test_does_not_ask_again():
    app = make_app(**AI_ON)
    make_user(app, role="admin")
    client = app.test_client()
    log_in(client)
    with patch("services.ai_service.requests.post", return_value=anthropic_answer()) as mock_post:
        response = client.post("/ai/test")
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/ai/status")
        client.get("/ai/status")
        client.get("/ai/status")
    assert mock_post.call_count == 1
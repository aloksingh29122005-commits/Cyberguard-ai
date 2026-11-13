"""Shared test setup. Every test gets a fresh app with an empty in-memory database."""
import pytest

from app import create_app
from database.db import db

TEST_CONFIG = {
    "TESTING": True,
    "SECRET_KEY": "test-secret-key-not-for-real-use",
    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    "SESSION_COOKIE_SECURE": False,  # the test client uses plain http
    "WTF_CSRF_ENABLED": False,  # CSRF has its own tests that turn it back on
}


@pytest.fixture()
def app():
    app = create_app(dict(TEST_CONFIG))
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()
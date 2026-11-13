"""Tests for the dashboard numbers and the dashboard page."""
from datetime import timedelta

from database.db import db
from database.seed_demo import add_demo_data
from models.alert import Alert
from models.scan import Scan
from models.user import User
from services.dashboard_service import ACTIVITY_DAYS, RECENT_LIMIT, get_dashboard_data
from services.risk_engine import get_risk_level
from utils.helpers import utc_now

PASSWORD = "StrongPass123"


def make_user(app, username="owner", email="owner@example.com"):
    with app.app_context():
        user = User(username=username, email=email)
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()
        return user.id


def add_scan(user_id, score, days_ago=0, hours_ago=0):
    scan = Scan(
        user_id=user_id, scan_type="url", target=f"http://test{score}.example",
        risk_score=score, risk_level=get_risk_level(score),
        created_at=utc_now() - timedelta(days=days_ago, hours=hours_ago),
    )
    db.session.add(scan)
    return scan


def add_alert(user_id, severity, status="Open"):
    db.session.add(Alert(
        user_id=user_id, alert_type="Suspicious URL", severity=severity,
        source="URL scanner", description="Example alert", status=status,
    ))


def log_in(client, email="owner@example.com"):
    return client.post("/login", data={"email": email, "password": PASSWORD}, follow_redirects=True)


# ---------- The numbers ----------

def test_new_user_sees_zeros(app):
    user_id = make_user(app)
    with app.app_context():
        data = get_dashboard_data(user_id)
        assert data["total_scans"] == 0
        assert data["total_threats"] == 0
        assert data["alert_counts"] == {"Critical": 0, "High": 0, "Medium": 0}
        assert [level["count"] for level in data["levels"]] == [0, 0, 0, 0, 0]
        assert len(data["activity"]["labels"]) == ACTIVITY_DAYS
        assert sum(data["activity"]["counts"]) == 0
        assert data["recent_scans"] == []
        assert data["has_demo"] is False


def test_counts_scans_threats_and_open_alerts(app):
    user_id = make_user(app)
    with app.app_context():
        for score in (10, 45, 70, 95):
            add_scan(user_id, score)
        add_alert(user_id, "Critical")
        add_alert(user_id, "High", status="Resolved")  # resolved alerts are not counted
        add_alert(user_id, "Medium", status="Acknowledged")
        db.session.commit()

        data = get_dashboard_data(user_id)
        assert data["total_scans"] == 4
        assert data["total_threats"] == 3  # scores 45, 70 and 95
        assert data["alert_counts"] == {"Critical": 1, "High": 0, "Medium": 1}
        counts_by_level = {level["name"]: level["count"] for level in data["levels"]}
        assert counts_by_level == {"Safe": 1, "Low": 0, "Medium": 1, "High": 1, "Critical": 1}


def test_one_user_never_sees_another_users_data(app):
    first_id = make_user(app, "first", "first@example.com")
    second_id = make_user(app, "second", "second@example.com")
    with app.app_context():
        add_scan(first_id, 90)
        add_alert(first_id, "Critical")
        db.session.commit()

        data = get_dashboard_data(second_id)
        assert data["total_scans"] == 0
        assert data["alert_counts"]["Critical"] == 0
        assert data["recent_alerts"] == []


def test_activity_counts_scans_per_day(app):
    user_id = make_user(app)
    with app.app_context():
        add_scan(user_id, 10)
        add_scan(user_id, 20)
        add_scan(user_id, 30, days_ago=3)
        add_scan(user_id, 40, days_ago=30)  # older than 14 days, so not counted
        db.session.commit()

        counts = get_dashboard_data(user_id)["activity"]["counts"]
        assert len(counts) == ACTIVITY_DAYS
        assert counts[-1] == 2   # today
        assert counts[-4] == 1   # three days ago
        assert sum(counts) == 3


def test_recent_scans_are_newest_first_and_limited(app):
    user_id = make_user(app)
    with app.app_context():
        for hours_ago in range(RECENT_LIMIT + 3):
            add_scan(user_id, hours_ago, hours_ago=hours_ago)
        db.session.commit()

        recent = get_dashboard_data(user_id)["recent_scans"]
        assert len(recent) == RECENT_LIMIT
        times = [scan.created_at for scan in recent]
        assert times == sorted(times, reverse=True)


# ---------- The page ----------

def test_page_shows_empty_state_without_charts(app, client):
    make_user(app)
    page = log_in(client).get_data(as_text=True)
    assert "No scans yet" in page
    assert "Total scans" in page
    assert "activityChart" not in page


def test_page_shows_charts_when_there_are_scans(app, client):
    user_id = make_user(app)
    with app.app_context():
        add_scan(user_id, 50)
        db.session.commit()
    page = log_in(client).get_data(as_text=True)
    assert "activityChart" in page
    assert "levelChart" in page
    assert "dashboard-data" in page
    assert "Demo data" not in page


def test_page_marks_demo_data(app, client):
    user_id = make_user(app)
    with app.app_context():
        add_demo_data(user_id)
    page = log_in(client).get_data(as_text=True)
    assert "You are looking at demo data" in page
    assert "demo-tag" in page
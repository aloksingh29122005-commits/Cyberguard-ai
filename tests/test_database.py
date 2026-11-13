"""Tests for the Scan and Alert tables and the demo data."""
from database.db import db
from database.seed_demo import DEMO_SCANS, add_demo_data, clear_demo_data
from models.alert import Alert
from models.scan import Scan
from models.user import User
from services.risk_engine import THREAT_MIN_SCORE, get_risk_level


def make_user(app, username="owner", email="owner@example.com"):
    with app.app_context():
        user = User(username=username, email=email)
        user.set_password("StrongPass123")
        db.session.add(user)
        db.session.commit()
        return user.id


def test_scan_belongs_to_user_and_keeps_indicators(app):
    with app.app_context():
        user = User(username="owner", email="owner@example.com")
        user.set_password("StrongPass123")
        scan = Scan(
            user=user, scan_type="url", target="http://x.example",
            risk_score=15, risk_level="Safe",
            indicators=[{"text": "The link does not use HTTPS", "points": 15}],
        )
        db.session.add_all([user, scan])
        db.session.commit()

        saved = Scan.query.first()
        assert saved.user.username == "owner"
        assert saved.indicators[0]["points"] == 15
        assert saved.is_demo is False
        assert saved.type_label == "URL"
        assert user.scans[0].id == saved.id


def test_alert_links_to_scan_and_has_a_display_id(app):
    with app.app_context():
        user = User(username="owner", email="owner@example.com")
        user.set_password("StrongPass123")
        scan = Scan(user=user, scan_type="url", target="http://x.example", risk_score=50, risk_level="Medium")
        alert = Alert(
            user=user, scan=scan, alert_type="Suspicious URL", severity="Medium",
            source="URL scanner", description="Example alert",
        )
        db.session.add_all([user, scan, alert])
        db.session.commit()

        assert alert.status == "Open"
        assert alert.display_id == f"ALT-{alert.id:04d}"
        assert scan.alerts == [alert]


def test_deleting_a_user_deletes_their_scans_and_alerts(app):
    with app.app_context():
        user = User(username="owner", email="owner@example.com")
        user.set_password("StrongPass123")
        scan = Scan(user=user, scan_type="url", target="http://x.example", risk_score=50, risk_level="Medium")
        alert = Alert(
            user=user, scan=scan, alert_type="Suspicious URL", severity="Medium",
            source="URL scanner", description="Example alert",
        )
        db.session.add_all([user, scan, alert])
        db.session.commit()

        db.session.delete(user)
        db.session.commit()
        assert Scan.query.count() == 0
        assert Alert.query.count() == 0


def test_demo_scores_come_from_the_warning_signs(app):
    user_id = make_user(app)
    with app.app_context():
        scans_added, alerts_added = add_demo_data(user_id)
        scans = Scan.query.filter_by(user_id=user_id).all()

        assert scans_added == len(DEMO_SCANS) == len(scans)
        for scan in scans:
            assert scan.is_demo is True
            assert scan.risk_score == min(100, sum(item["points"] for item in scan.indicators))
            assert scan.risk_level == get_risk_level(scan.risk_score)

        threats = [scan for scan in scans if scan.risk_score >= THREAT_MIN_SCORE]
        assert alerts_added == len(threats)
        assert Alert.query.filter_by(user_id=user_id, is_demo=True).count() == len(threats)


def test_demo_data_is_not_added_twice(app):
    user_id = make_user(app)
    with app.app_context():
        add_demo_data(user_id)
        assert add_demo_data(user_id) == (0, 0)
        assert Scan.query.count() == len(DEMO_SCANS)


def test_clearing_demo_data_keeps_real_scans(app):
    user_id = make_user(app)
    with app.app_context():
        add_demo_data(user_id)
        db.session.add(Scan(
            user_id=user_id, scan_type="url", target="http://real.example",
            risk_score=0, risk_level="Safe", is_demo=False,
        ))
        db.session.commit()

        scans_removed, alerts_removed = clear_demo_data(user_id)

        assert scans_removed == len(DEMO_SCANS)
        assert alerts_removed > 0
        assert Scan.query.count() == 1
        assert Scan.query.first().target == "http://real.example"
        assert Alert.query.count() == 0
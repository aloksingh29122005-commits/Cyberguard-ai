"""Adds (or removes) clearly labelled DEMO data so the dashboard has something to show.

    python -m database.seed_demo          add demo data to one user
    python -m database.seed_demo clear    remove the demo data again

Demo rows are saved with is_demo=True and show a "Demo" tag on the dashboard.
Real scans are never touched.
"""
import sys
from datetime import timedelta

from app import create_app
from database.db import db
from models.alert import STATUS_ACKNOWLEDGED, STATUS_OPEN, STATUS_RESOLVED, Alert
from models.scan import Scan
from models.user import User
from services.risk_engine import THREAT_MIN_SCORE, clamp_score, get_risk_level
from utils.helpers import utc_now

# Warning signs and the points each one adds (the same idea as the Phase 7 risk engine)
NO_HTTPS = ("The link does not use HTTPS", 15)
IP_ADDRESS = ("The address is an IP number, not a normal name", 20)
KEYWORDS = ("Suspicious words found (login, verify, secure)", 15)
SUBDOMAINS = ("Too many subdomains in the address", 10)
ODD_CHARACTERS = ("Unusual characters in the address", 10)
URGENCY = ("Pushes you to act quickly", 15)
CREDENTIALS = ("Asks for a password, PIN or OTP", 25)
MONEY = ("Asks for money or card details", 25)

# (days ago, hours ago, scan type, target, warning signs found)
DEMO_SCANS = [
    (0, 1, "url", "http://192.168.10.25/login/verify", [IP_ADDRESS, NO_HTTPS, KEYWORDS]),
    (0, 5, "email", "Email: Your account will be closed today", [URGENCY, CREDENTIALS]),
    (1, 3, "scam", "Message: Send your OTP to claim a prize", [URGENCY, CREDENTIALS, MONEY]),
    (1, 9, "url", "https://docs.python.org/3/", []),
    (2, 2, "url", "http://secure-login.mybank-update.example/verify",
     [NO_HTTPS, KEYWORDS, SUBDOMAINS, ODD_CHARACTERS]),
    (2, 7, "email", "Email: Invoice overdue, pay now to avoid penalty", [URGENCY, MONEY, KEYWORDS]),
    (3, 4, "scam", "Message: Job offer, pay a small fee to start", [MONEY, URGENCY]),
    (3, 8, "url", "https://news.example.org/article/12", []),
    (4, 1, "email", "Email: Confirm your bank login details", [CREDENTIALS, MONEY, KEYWORDS, URGENCY]),
    (5, 6, "url", "http://account-verify.example/login@update", [NO_HTTPS, KEYWORDS, ODD_CHARACTERS]),
    (6, 2, "scam", "Message: Your account is blocked, share your PIN", [CREDENTIALS, URGENCY, KEYWORDS]),
    (6, 10, "url", "http://185.20.4.9/secure/login/update",
     [IP_ADDRESS, NO_HTTPS, KEYWORDS, ODD_CHARACTERS, SUBDOMAINS]),
    (8, 3, "email", "Email: Team meeting notes for Friday", []),
    (9, 5, "email", "Email: Verify your payroll account and bank details",
     [CREDENTIALS, MONEY, KEYWORDS, NO_HTTPS, SUBDOMAINS]),
    (10, 2, "scam", "Message: Lottery winner, pay tax to receive money", [MONEY, URGENCY, KEYWORDS]),
    (11, 6, "url", "https://library.example.edu/search", []),
    (12, 4, "url", "http://192.0.2.44/bank/login", [IP_ADDRESS, NO_HTTPS, KEYWORDS, CREDENTIALS]),
    (13, 1, "scam", "Message: Urgent! Pay now or your SIM will be blocked",
     [MONEY, URGENCY, CREDENTIALS, KEYWORDS, NO_HTTPS]),
]

ALERT_TYPES = {"url": "Suspicious URL", "email": "Phishing email", "scam": "Scam message"}
ALERT_SOURCES = {"url": "URL scanner", "email": "Email analyzer", "scam": "Scam detector"}


def demo_alert_status(level, days_ago):
    """Critical alerts stay open, old alerts are resolved, the rest are in between."""
    if level == "Critical":
        return STATUS_OPEN
    if days_ago >= 8:
        return STATUS_RESOLVED
    if days_ago <= 2:
        return STATUS_OPEN
    return STATUS_ACKNOWLEDGED


def add_demo_data(user_id):
    """Add demo scans (and the alerts they raise) for one user. Returns (scans, alerts) added."""
    if Scan.query.filter_by(user_id=user_id, is_demo=True).first():
        return 0, 0  # demo data is already there

    now = utc_now()
    scans_added = 0
    alerts_added = 0

    for days_ago, hours_ago, scan_type, target, signs in DEMO_SCANS:
        indicators = [{"text": text, "points": points} for text, points in signs]
        if not indicators:
            indicators = [{"text": "No warning signs found", "points": 0}]

        # The score is the total of the points, never a random number
        score = clamp_score(sum(item["points"] for item in indicators))
        level = get_risk_level(score)
        created_at = now - timedelta(days=days_ago, hours=hours_ago)

        scan = Scan(
            user_id=user_id,
            scan_type=scan_type,
            target=target,
            risk_score=score,
            risk_level=level,
            indicators=indicators,
            explanation="Demo example. This is not a real scan.",
            is_demo=True,
            created_at=created_at,
        )
        db.session.add(scan)
        scans_added += 1

        if score >= THREAT_MIN_SCORE:
            main_sign = max(indicators, key=lambda item: item["points"])
            db.session.add(Alert(
                user_id=user_id,
                scan=scan,
                alert_type=ALERT_TYPES[scan_type],
                severity=level,
                source=ALERT_SOURCES[scan_type],
                description=f"Risk score {score} ({level}). Main sign: {main_sign['text'].lower()}.",
                status=demo_alert_status(level, days_ago),
                is_demo=True,
                created_at=created_at,
            ))
            alerts_added += 1

    db.session.commit()
    return scans_added, alerts_added


def clear_demo_data(user_id):
    """Remove only the demo rows of one user. Returns (scans, alerts) removed."""
    alerts_removed = Alert.query.filter_by(user_id=user_id, is_demo=True).delete()
    scans_removed = Scan.query.filter_by(user_id=user_id, is_demo=True).delete()
    db.session.commit()
    return scans_removed, alerts_removed


def main():
    action = sys.argv[1].lower() if len(sys.argv) > 1 else "add"
    if action not in ("add", "clear"):
        print("Use:  python -m database.seed_demo         (add demo data)")
        print("  or: python -m database.seed_demo clear   (remove demo data)")
        return

    app = create_app()
    with app.app_context():
        email = input("Email of the user: ").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user is None:
            print("No user with that email. Register first, then run this again.")
            return

        if action == "clear":
            scans, alerts = clear_demo_data(user.id)
            print(f"Removed {scans} demo scans and {alerts} demo alerts.")
        else:
            scans, alerts = add_demo_data(user.id)
            if scans == 0:
                print("This user already has demo data. Nothing was added.")
            else:
                print(f"Added {scans} demo scans and {alerts} demo alerts. Refresh the dashboard.")


if __name__ == "__main__":
    main()
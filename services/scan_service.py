"""Saves scan results. Every scanner (URL, email, message, password) uses this file."""
from database.db import db
from models.alert import Alert
from models.scan import Scan
from services.risk_engine import THREAT_MIN_SCORE

MAX_TARGET_LENGTH = 500  # the length of the Scan.target column

ALERT_TYPES = {
    "url": "Suspicious URL",
    "email": "Phishing email",
    "scam": "Scam message",
    "password": "Weak password",
}
ALERT_SOURCES = {
    "url": "URL scanner",
    "email": "Email analyzer",
    "scam": "Scam detector",
    "password": "Password analyzer",
}


def save_scan(user_id, scan_type, target, result):
    """Save a scan. A Medium, High or Critical result also raises an alert. Returns the Scan."""
    if len(target) > MAX_TARGET_LENGTH:
        target = target[:MAX_TARGET_LENGTH - 3] + "..."

    scan = Scan(
        user_id=user_id,
        scan_type=scan_type,
        target=target,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        indicators=result["indicators"],
        explanation=result["explanation"],
    )
    db.session.add(scan)

    if scan.risk_score >= THREAT_MIN_SCORE:
        main_sign = max(result["indicators"], key=lambda item: item["points"])
        db.session.add(Alert(
            user_id=user_id,
            scan=scan,
            alert_type=ALERT_TYPES[scan_type],
            severity=scan.risk_level,
            source=ALERT_SOURCES[scan_type],
            description=f"Risk score {scan.risk_score} ({scan.risk_level}). Main sign: {main_sign['text']}.",
        ))

    db.session.commit()
    return scan
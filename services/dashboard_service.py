"""Collects the numbers shown on the dashboard. The route calls get_dashboard_data()."""
from collections import Counter
from datetime import datetime, time, timedelta, timezone

from sqlalchemy import func

from database.db import db
from models.alert import STATUS_RESOLVED, Alert
from models.scan import Scan
from services.risk_engine import LEVEL_NAMES, THREAT_MIN_SCORE
from utils.helpers import to_local, utc_now

ACTIVITY_DAYS = 14
RECENT_LIMIT = 5
ALERT_CARDS = ("Critical", "High", "Medium")


def get_dashboard_data(user_id):
    """Everything the dashboard needs for ONE user, as a dictionary."""
    scans = Scan.query.filter_by(user_id=user_id)

    total_scans = scans.count()
    total_threats = scans.filter(Scan.risk_score >= THREAT_MIN_SCORE).count()

    # Alerts that are not resolved yet, counted by severity
    alert_rows = (
        db.session.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.user_id == user_id, Alert.status != STATUS_RESOLVED)
        .group_by(Alert.severity)
        .all()
    )
    open_alerts = dict(alert_rows)
    alert_counts = {name: open_alerts.get(name, 0) for name in ALERT_CARDS}

    # Number of scans at each risk level (Safe, Low, Medium, High, Critical)
    level_rows = (
        db.session.query(Scan.risk_level, func.count(Scan.id))
        .filter(Scan.user_id == user_id)
        .group_by(Scan.risk_level)
        .all()
    )
    scans_by_level = dict(level_rows)
    levels = [{"name": name, "count": scans_by_level.get(name, 0)} for name in LEVEL_NAMES]

    return {
        "total_scans": total_scans,
        "total_threats": total_threats,
        "alert_counts": alert_counts,
        "levels": levels,
        "activity": get_scan_activity(user_id),
        "recent_scans": scans.order_by(Scan.created_at.desc()).limit(RECENT_LIMIT).all(),
        "recent_alerts": (
            Alert.query.filter_by(user_id=user_id)
            .order_by(Alert.created_at.desc())
            .limit(RECENT_LIMIT)
            .all()
        ),
        "has_demo": scans.filter_by(is_demo=True).first() is not None,
    }


def get_scan_activity(user_id):
    """Scans per day for the last 14 days (days with no scans show 0)."""
    today = to_local(utc_now()).date()
    first_day = today - timedelta(days=ACTIVITY_DAYS - 1)

    # Midnight of the first day, converted to UTC because the database stores UTC
    window_start = datetime.combine(first_day, time.min).astimezone(timezone.utc).replace(tzinfo=None)

    rows = (
        db.session.query(Scan.created_at)
        .filter(Scan.user_id == user_id, Scan.created_at >= window_start)
        .all()
    )
    scans_per_day = Counter(to_local(row[0]).date() for row in rows)

    days = [first_day + timedelta(days=i) for i in range(ACTIVITY_DAYS)]
    return {
        "labels": [day.strftime("%d %b") for day in days],
        "counts": [scans_per_day.get(day, 0) for day in days],
    }
"""The Alert table: a warning raised for the user, usually from a risky scan."""
from database.db import db
from utils.helpers import utc_now

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")

STATUS_OPEN = "Open"
STATUS_ACKNOWLEDGED = "Acknowledged"
STATUS_RESOLVED = "Resolved"
STATUSES = (STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_RESOLVED)


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"))  # empty if the alert has no scan
    alert_type = db.Column(db.String(40), nullable=False)
    severity = db.Column(db.String(15), nullable=False)
    source = db.Column(db.String(40), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(15), nullable=False, default=STATUS_OPEN)
    is_demo = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now, index=True)

    user = db.relationship("User", back_populates="alerts")
    scan = db.relationship("Scan", back_populates="alerts")

    @property
    def display_id(self):
        """The Alert ID shown on screen, for example ALT-0007."""
        if self.id is None:
            return "ALT-new"
        return f"ALT-{self.id:04d}"
"""The Scan table: one row for every URL, email, message or password check.

`indicators` is a list of the warning signs found, for example:
    [{"text": "The link does not use HTTPS", "points": 15}]
The risk score is the total of those points (limited to 0-100).
"""
from database.db import db
from utils.helpers import utc_now

SCAN_TYPE_LABELS = {
    "url": "URL",
    "email": "Email",
    "scam": "Message",
    "password": "Password",
}


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    scan_type = db.Column(db.String(20), nullable=False)  # url, email, scam or password
    target = db.Column(db.String(500), nullable=False)    # for passwords we never store the real one
    risk_score = db.Column(db.Integer, nullable=False)    # 0 to 100
    risk_level = db.Column(db.String(10), nullable=False)  # Safe, Low, Medium, High or Critical
    indicators = db.Column(db.JSON, nullable=False, default=list)
    explanation = db.Column(db.Text, nullable=False, default="")
    ai_explanation = db.Column(db.Text)                   # filled in later by the AI (can stay empty)
    is_demo = db.Column(db.Boolean, nullable=False, default=False)  # True for example data
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now, index=True)

    user = db.relationship("User", back_populates="scans")
    alerts = db.relationship("Alert", back_populates="scan")

    @property
    def type_label(self):
        """A friendly name for the scan type, for example 'URL'."""
        return SCAN_TYPE_LABELS.get(self.scan_type, self.scan_type)
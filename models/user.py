"""The User table: one row per person who registers."""
from werkzeug.security import check_password_hash, generate_password_hash

from database.db import db
from utils.helpers import utc_now

ROLE_USER = "user"
ROLE_ADMIN = "admin"


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  # never the real password
    role = db.Column(db.String(10), nullable=False, default=ROLE_USER)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    # One user has many scans and many alerts. Deleting the user deletes them too.
    scans = db.relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    alerts = db.relationship("Alert", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password):
        """Turn the password into a salted hash and keep only the hash."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """True if this password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == ROLE_ADMIN
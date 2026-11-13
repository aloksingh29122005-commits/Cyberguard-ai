"""The shared database object. Every model and route imports `db` from here."""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
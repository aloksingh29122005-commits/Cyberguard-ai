"""Importing the models here lets SQLAlchemy know about every table."""
from models.user import User  # noqa: F401
from models.scan import Scan  # noqa: F401
from models.alert import Alert  # noqa: F401
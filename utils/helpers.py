"""Small helper functions used in many places."""
from datetime import datetime, timezone


def utc_now():
    """Current time in UTC. We store every time in UTC."""
    return datetime.now(timezone.utc)


def to_local(value):
    """Convert a UTC time from the database to this computer's own time zone."""
    return value.replace(tzinfo=timezone.utc).astimezone()


def local_time(value, fmt="%d %b %Y, %H:%M"):
    """Text version of a stored UTC time, shown in local time. Used as a template filter."""
    if value is None:
        return ""
    return to_local(value).strftime(fmt)
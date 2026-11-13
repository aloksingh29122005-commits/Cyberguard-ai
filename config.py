"""Settings for CyberGuard AI.

Secret values (like SECRET_KEY and AI_API_KEY) are read from the .env file,
so they never appear inside the code.
"""
import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# Read the .env file and put its values into environment variables
load_dotenv(BASE_DIR / ".env")

# Example values that must never be used as a real key
PLACEHOLDER_KEYS = {"", "change_me", "your_secret_key"}


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "")

    # The database is one file called cyberguard.db in the project folder
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + (BASE_DIR / "cyberguard.db").as_posix()

    # Session cookie safety
    SESSION_COOKIE_HTTPONLY = True   # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE = "Lax"  # the cookie is not sent with cross-site form posts
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)  # automatic logout after 2 hours

    # A CSRF token stays valid for as long as the session lives
    WTF_CSRF_TIME_LIMIT = None

    # AI connection (see .env.example). With AI_PROVIDER=none the whole app works without any AI.
    # The values are read as text here; services/ai_service.py checks them and uses safe defaults.
    AI_PROVIDER = os.environ.get("AI_PROVIDER", "none")
    AI_API_KEY = os.environ.get("AI_API_KEY", "")
    AI_MODEL = os.environ.get("AI_MODEL", "")
    AI_BASE_URL = os.environ.get("AI_BASE_URL", "")
    AI_TIMEOUT_SECONDS = os.environ.get("AI_TIMEOUT_SECONDS", "30")
    AI_MAX_OUTPUT_TOKENS = os.environ.get("AI_MAX_OUTPUT_TOKENS", "600")
    AI_MAX_CALLS_PER_HOUR = os.environ.get("AI_MAX_CALLS_PER_HOUR", "30")
"""Checks for what users type into forms. Each function returns an error text, or None if all is fine."""
import re

USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_]{3,30}")
EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

# A tiny list of very common passwords (Phase 6 adds a proper password analyzer)
COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "qwerty123", "welcome1", "admin123", "letmein1", "iloveyou1",
}


def validate_username(username):
    if not USERNAME_PATTERN.fullmatch(username):
        return "Username must be 3 to 30 characters: letters, numbers and underscore only."
    return None


def validate_email(email):
    if len(email) > 120 or not EMAIL_PATTERN.fullmatch(email):
        return "Please enter a valid email address."
    return None


def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if len(password) > 128:
        return "Password must be 128 characters or fewer."
    if not re.search(r"[a-z]", password):
        return "Password needs at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return "Password needs at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return "Password needs at least one number."
    if password.lower() in COMMON_PASSWORDS:
        return "That password is too common. Choose one that is harder to guess."
    return None


def validate_registration(username, email, password, confirm_password):
    """Check the whole registration form and return a list of error texts."""
    errors = []
    for problem in (validate_username(username), validate_email(email), validate_password(password)):
        if problem:
            errors.append(problem)
    if password != confirm_password:
        errors.append("Passwords do not match.")
    return errors
"""Password analyzer: checks how strong a password is, completely locally.

PRIVACY RULES (do not break them):
  * The password is only held in memory while it is being checked.
  * It is never saved, never logged, never put in an error message and never
    sent anywhere, not even to the AI.
  * The result holds only general findings such as "No capital letters".
    No finding mentions the password itself, not even a part of it or its length.

The risk score is the total of the points of the weaknesses found (more points =
weaker password). It is rule-based, not AI.
"""
import re

from services.risk_engine import calculate_score, get_risk_level, make_indicator

MAX_PASSWORD_LENGTH = 128
LONG_PASSWORD = 16   # from this length on, a password does not need every kind of character
MIN_WORD_LENGTH = 3  # shorter personal words (like "al") are ignored

TARGET_LABEL = "Password check (password not stored)"

# ---------- The rules: how many points each weakness adds ----------
POINTS = {
    "common_password": 70,
    "mostly_sequence": 60,
    "few_unique": 40,
    "common_word": 30,
    "personal_info": 25,
    "sequence": 15,
    "keyboard_pattern": 15,
    "repeats": 10,
    "no_lowercase": 10,
    "no_uppercase": 10,
    "no_digits": 10,
    "no_symbols": 10,
}

# A password shorter than the first number of a pair gets the points of that pair
LENGTH_POINTS = [(6, 45), (8, 40), (10, 30), (12, 20), (14, 10), (16, 5)]

# ---------- Lists the rules use ----------
# Very common passwords. Attackers try these first. (A small list; real tools use millions.)
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "696969", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321", "superman",
    "1qaz2wsx", "7777777", "121212", "000000", "qazwsx", "123qwe", "killer",
    "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
    "112233", "george", "computer", "michelle", "jessica", "pepper", "zxcvbn",
    "555555", "11111111", "131313", "freedom", "777777", "maggie", "159753",
    "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer",
    "ashley", "nicole", "chelsea", "biteme", "matthew", "access", "yankees",
    "987654321", "dallas", "austin", "thunder", "taylor", "matrix", "welcome",
    "admin", "admin123", "password1", "password123", "passw0rd", "p@ssw0rd",
    "qwerty123", "letmein1", "welcome1", "iloveyou1", "abcd1234", "india123",
    "admin@123", "root", "login", "changeme", "default", "guest", "test123",
    "secret", "pass123", "hello123", "monkey123", "dragon123", "abc12345",
    "1q2w3e4r", "q1w2e3r4", "qwerty1", "samsung", "lovely", "whatever",
    "flower", "sweety", "naruto", "pokemon", "internet", "cricket", "krishna",
}

# Words from the list above that are long enough to look for inside a longer password
COMMON_WORDS = sorted(word for word in COMMON_PASSWORDS if len(word) >= 6 and not word.isdigit())

# People swap letters for look-alikes: p@ssw0rd -> password
LOOKALIKES = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "l", "3": "e", "$": "s", "5": "s", "7": "t", "!": "i"})

# Rows of a keyboard. Four keys next to each other in a row (or backwards) is a pattern.
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsx", "qweasd"]

# ---------- Texts shown to the user ----------
WHY = {
    "common_password": "This is one of the first passwords attackers try. It can be guessed in seconds.",
    "few_unique": "Using only a few different characters makes a password very easy to guess.",
    "common_word": "Passwords built around well-known words or common passwords are guessed quickly.",
    "personal_info": "Attackers try your name, username and email first. Personal words make a password easy to guess.",
    "mostly_sequence": "A password that is mostly a sequence like abc or 123 is among the first things a guessing program tries.",
    "sequence": "Sequences like abc or 123 are among the first patterns a guessing program tries.",
    "keyboard_pattern": "Keyboard patterns like qwerty are on every list of common patterns.",
    "repeats": "Repeated characters or repeated pieces make a password shorter than it looks.",
    "length": "Length matters most. Every extra character multiplies the work needed to guess the password.",
    "no_lowercase": "Mixing kinds of characters gives attackers more possibilities to try.",
    "no_uppercase": "Mixing kinds of characters gives attackers more possibilities to try.",
    "no_digits": "Mixing kinds of characters gives attackers more possibilities to try.",
    "no_symbols": "Mixing kinds of characters gives attackers more possibilities to try.",
}

ADVICE_BY_CODE = {
    "length": "Make it longer, at least 14 characters. A passphrase of four or five random words is easy to remember and hard to guess.",
    "common_password": "Choose something that is not on lists of common passwords. Attackers try those first.",
    "common_word": "Do not build your password around a common word like 'password' or 'welcome'.",
    "personal_info": "Do not use your name, username or email in your password.",
    "mostly_sequence": "Avoid sequences like abc or 123. Use characters that follow no order.",
    "sequence": "Avoid sequences like abc or 123.",
    "keyboard_pattern": "Avoid keyboard patterns like qwerty.",
    "repeats": "Avoid repeated characters like aaa or repeated pieces like abcabc.",
    "few_unique": "Use many different characters instead of repeating a few.",
    "no_lowercase": "Mix lowercase letters, capital letters, numbers and symbols, or make the password longer.",
    "no_uppercase": "Mix lowercase letters, capital letters, numbers and symbols, or make the password longer.",
    "no_digits": "Mix lowercase letters, capital letters, numbers and symbols, or make the password longer.",
    "no_symbols": "Mix lowercase letters, capital letters, numbers and symbols, or make the password longer.",
}

ADVICE_BY_STRENGTH = {
    "Strong": [
        "Keep this kind of password: long and not based on personal words. Use it for only one account.",
        "Store it in a password manager instead of writing it down.",
    ],
    "Moderate": [
        "This password is acceptable, but a longer one is safer. Add more words or characters.",
        "Use a different password for every account, and turn on two-step verification where you can.",
    ],
    "Weak": [
        "Do not use this password for anything important.",
        "Change it to a passphrase of four or five random words, or a random password of 14 or more characters.",
        "If you already use it anywhere, change it there now.",
        "Use a different password for every account, and turn on two-step verification where you can.",
    ],
}

STRENGTH_SENTENCES = {
    "Strong": "This password is strong. It is long and has no obvious weak points.",
    "Moderate": "This password is moderate. It is better than many, but it can be stronger.",
    "Weak": "This password is weak. A guessing program could find it quickly.",
}

PRIVACY_NOTE = (
    "The password was checked by this app only. It was not saved, not written to any log "
    "and not sent to anyone, including the AI."
)


class PasswordError(ValueError):
    """The text cannot be checked. The message never contains the password."""


# ---------- Step 1: small helper checks ----------
def kinds_of_characters(password):
    """Which kinds of characters the password has."""
    return {
        "lowercase": re.search(r"[a-z]", password) is not None,
        "uppercase": re.search(r"[A-Z]", password) is not None,
        "digits": re.search(r"[0-9]", password) is not None,
        "symbols": re.search(r"[^A-Za-z0-9]", password) is not None,
    }


def length_points(length):
    """How many points a password of this length gets (0 for 16 or more characters)."""
    for limit, points in LENGTH_POINTS:
        if length < limit:
            return points
    return 0


def is_common_password(password):
    """True if the password, or the password without trailing numbers or look-alike swaps, is very common."""
    lowered = password.lower()
    forms = {lowered, lowered.translate(LOOKALIKES)}
    for form in list(forms):
        forms.add(form.rstrip("0123456789!@#$%^&*._-"))
    forms.discard("")
    return any(form in COMMON_PASSWORDS for form in forms)


def has_common_word(password):
    """True if a long common password or word is hidden inside the password."""
    lowered = password.lower()
    unswapped = lowered.translate(LOOKALIKES)
    return any(word in lowered or word in unswapped for word in COMMON_WORDS)


def sequence_share(password):
    """The share (0 to 1) of the characters that sit inside a run of three in a row, like abc, cba, 123 or 321."""
    chars = password.lower()
    covered = set()
    for index in range(len(chars) - 2):
        first, second, third = chars[index], chars[index + 1], chars[index + 2]
        step = ord(second) - ord(first)
        if step in (1, -1) and ord(third) - ord(second) == step and (first + second + third).isalnum():
            covered.update((index, index + 1, index + 2))
    return len(covered) / len(chars) if chars else 0.0


def has_keyboard_pattern(password):
    """True for four keys next to each other on a keyboard row, forwards or backwards."""
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for text in (row, row[::-1]):
            if any(text[i:i + 4] in lowered for i in range(len(text) - 3)):
                return True
    return False


def has_repeats(password):
    """True for aaa (3 of the same in a row) or a piece repeated right after itself, like abab or xyzxyz."""
    return re.search(r"(.)\1{2,}", password) is not None or re.search(r"(.{2,})\1", password) is not None


def has_few_unique_characters(password):
    """True if the password has 4 or more characters but only 3 or fewer different ones."""
    return len(password) >= 4 and len(set(password.lower())) <= 3


def uses_personal_words(password, personal_words):
    """True if the password contains the user's own words (username, name of the email)."""
    lowered = password.lower()
    for word in personal_words or ():
        word = (word or "").strip().lower()
        if len(word) >= MIN_WORD_LENGTH and word in lowered:
            return True
    return False


# ---------- Step 2: find the weaknesses and the good points ----------
def find_findings(password, personal_words=()):
    """Return a list of findings: weaknesses (with points) and good points (0 points, good=True)."""
    findings = []

    def problem(code, text):
        findings.append(make_indicator(code, text, POINTS[code], WHY[code]))

    def good(code, text):
        item = make_indicator(code, text, 0)
        item["good"] = True
        findings.append(item)

    length = len(password)
    points = length_points(length)
    if points:
        text = ("The password is short (less than 12 characters)" if length < 12
                else "The password could be longer (less than 16 characters)")
        findings.append(make_indicator("length", text, points, WHY["length"]))
    else:
        good("length_ok", "Long (16 or more characters)")

    # Mixing kinds of characters is only asked from shorter passwords
    kinds = kinds_of_characters(password)
    labels = {
        "lowercase": ("no_lowercase", "No lowercase letters", "Has lowercase letters"),
        "uppercase": ("no_uppercase", "No capital letters", "Has capital letters"),
        "digits": ("no_digits", "No numbers", "Has numbers"),
        "symbols": ("no_symbols", "No symbols or spaces", "Has symbols or spaces"),
    }
    for kind, (code, missing_text, present_text) in labels.items():
        if kinds[kind]:
            good(kind + "_ok", present_text)
        elif length < LONG_PASSWORD:
            problem(code, missing_text)

    if is_common_password(password):
        problem("common_password", "This is one of the most common passwords")
    else:
        good("common_password_ok", "Not one of the most common passwords")
        if has_common_word(password):
            problem("common_word", "Contains a very common word or password")

    if uses_personal_words(password, personal_words):
        problem("personal_info", "Contains part of your username or email")

    share = sequence_share(password)
    if share >= 0.5:
        problem("mostly_sequence", "Is mostly a simple sequence like abc or 123")
    elif share > 0:
        problem("sequence", "Contains a simple sequence like abc or 123")
    else:
        good("sequence_ok", "No simple sequences like abc or 123")

    if has_keyboard_pattern(password):
        problem("keyboard_pattern", "Contains a keyboard pattern like qwer")
    else:
        good("keyboard_pattern_ok", "No keyboard patterns like qwer")

    if has_repeats(password):
        problem("repeats", "Contains repeated characters or a repeated piece")
    else:
        good("repeats_ok", "No repeated characters or repeated pieces")

    if has_few_unique_characters(password):
        problem("few_unique", "Uses very few different characters")

    return findings


# ---------- Step 3: strength label, advice and the final result ----------
def get_strength(risk_score):
    """Turn a risk score into {'label': 'Weak', 'score': 35}. The score is the strength out of 100."""
    level = get_risk_level(risk_score)
    if level == "Safe":
        label = "Strong"
    elif level == "Low":
        label = "Moderate"
    else:
        label = "Weak"
    return {"label": label, "score": 100 - max(0, min(100, int(risk_score)))}


def get_recommendations(risk_level, codes):
    """Advice for the user: advice for the strength, then advice for each weakness."""
    label = {"Safe": "Strong", "Low": "Moderate"}.get(risk_level, "Weak")
    advice = list(ADVICE_BY_STRENGTH[label])
    for code in codes:
        line = ADVICE_BY_CODE.get(code)
        if line and line not in advice:
            advice.append(line)
    return advice


def analyze_password(password, personal_words=()):
    """Check one password and return the whole result. Raises PasswordError for unusable text.

    The result never contains the password. Do not pass it to anything else.
    """
    if not isinstance(password, str) or password == "":
        raise PasswordError("Please type a password to check.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordError(f"That password is longer than {MAX_PASSWORD_LENGTH} characters, which is more than this checker reads.")

    findings = find_findings(password, personal_words)
    findings.sort(key=lambda item: item["points"], reverse=True)  # weaknesses first, good points last

    score = calculate_score(findings)
    level = get_risk_level(score)
    strength = get_strength(score)

    explanation = (
        f"{STRENGTH_SENTENCES[strength['label']]} "
        f"Its risk score is {score} out of 100 ({level.lower()} risk). {PRIVACY_NOTE}"
    )
    return {
        "target": TARGET_LABEL,
        "risk_score": score,
        "risk_level": level,
        "indicators": findings,
        "explanation": explanation,
        "recommendations": get_recommendations(level, [item["code"] for item in findings if not item.get("good")]),
        "strength": strength,
    }
"""The risk engine: one place that defines how scores, levels and categories work.

How a score is made (the same for every scanner):
  1. A scanner looks for warning signs. Each sign is an "indicator" with points.
  2. The score is the TOTAL of the points, limited to 0-100. Nothing is random.
  3. The score decides the level: Safe, Low, Medium, High or Critical.

This file also knows which KIND of danger each warning sign belongs to (for the
"where the points come from" chart) and can list every rule of every scanner in
one table (for the "How scoring works" page).
"""

# ---------- Levels ----------
# (level name, lowest score, highest score), from the safest level to the most dangerous
RISK_LEVELS = [
    ("Safe", 0, 20),
    ("Low", 21, 40),
    ("Medium", 41, 60),
    ("High", 61, 80),
    ("Critical", 81, 100),
]

LEVEL_NAMES = [name for name, _, _ in RISK_LEVELS]

# From this score upwards (Medium or higher) a scan counts as a threat and raises an alert
THREAT_MIN_SCORE = 41

# One short sentence for each level, used in the written summary of a result
LEVEL_SENTENCES = {
    "Safe": "Nothing stands out as dangerous.",
    "Low": "A few small warning signs, so be careful.",
    "Medium": "Treat it as suspicious.",
    "High": "It is very likely unsafe.",
    "Critical": "It shows the classic pattern of an attack, so do not trust it.",
}

# ---------- Kinds of danger ----------
CATEGORY_LABELS = {
    "credentials": "Stealing logins or codes",
    "money": "Asking for money",
    "impersonation": "Pretending to be someone else",
    "pressure": "Pressure and tricks",
    "links": "Dangerous links",
    "malware": "Harmful files or apps",
    "password": "Weak password",
    "other": "Other signs",
}
CATEGORY_ORDER = list(CATEGORY_LABELS)

# Which kind of danger each warning sign belongs to (the key is the code of the sign)
RULE_CATEGORIES = {
    # stealing logins or codes
    "otp_request": "credentials", "credentials": "credentials", "account_verification": "credentials",
    # asking for money
    "financial": "money", "payment_request": "money", "reward_scam": "money",
    "job_scam": "money", "delivery_scam": "money",
    # pretending to be someone else
    "brand_impersonation": "impersonation", "brand_link_mismatch": "impersonation",
    "authority_impersonation": "impersonation", "reply_to_mismatch": "impersonation",
    # pressure and tricks
    "urgency": "pressure", "threats": "pressure", "account_threats": "pressure",
    "social_engineering": "pressure", "generic_greeting": "pressure",
    # dangerous links
    "no_https": "links", "ip_address": "links", "keywords": "links", "subdomains": "links",
    "at_sign": "links", "lookalike_chars": "links", "long_url": "links", "shortener": "links",
    "risky_tld": "links", "suspicious_links": "links", "risky_links": "links", "shortened_link": "links",
    # harmful files or apps
    "risky_attachment": "malware", "app_install": "malware",
    # weak password
    "common_password": "password", "mostly_sequence": "password", "few_unique": "password",
    "common_word": "password", "personal_info": "password", "sequence": "password",
    "keyboard_pattern": "password", "repeats": "password", "length": "password",
    "no_lowercase": "password", "no_uppercase": "password", "no_digits": "password", "no_symbols": "password",
}

# A short name for every warning sign, for the "How scoring works" page
RULE_NAMES = {
    "otp_request": "Asks for an OTP, PIN or code",
    "credentials": "Asks for a password, PIN, OTP or card details",
    "account_verification": "Asks you to verify or update your account",
    "financial": "Asks for money or payment details",
    "payment_request": "Asks for money, fees or QR payments",
    "reward_scam": "Offers a prize, lottery win or refund",
    "job_scam": "Offers an easy job or income",
    "delivery_scam": "Talks about a failed delivery or a fee",
    "brand_impersonation": "A known company's name used by someone else",
    "brand_link_mismatch": "A company name with a link to another website",
    "authority_impersonation": "Mentions police, tax or government officers",
    "reply_to_mismatch": "Reply-To address differs from the sender",
    "urgency": "Urgent wording",
    "threats": "Threats about your account or legal trouble",
    "account_threats": "Threats about your account, card, SIM or KYC",
    "social_engineering": "Secrecy or quick-favour tricks",
    "generic_greeting": "A generic greeting like 'Dear customer'",
    "no_https": "The link does not use HTTPS",
    "ip_address": "An IP number instead of a website name",
    "keywords": "Suspicious words in the link",
    "subdomains": "Too many subdomains",
    "at_sign": "An @ sign in the address",
    "lookalike_chars": "Lookalike letters in the website name",
    "long_url": "A very long link",
    "shortener": "A link-shortener",
    "risky_tld": "A website ending often used in scams",
    "suspicious_links": "A dangerous link",
    "risky_links": "A link with some warning signs",
    "shortened_link": "A shortened link",
    "risky_attachment": "A risky file name or 'enable macros'",
    "app_install": "Asks you to install an app or give remote access",
    "common_password": "One of the most common passwords",
    "mostly_sequence": "Mostly a sequence like abc or 123",
    "few_unique": "Very few different characters",
    "common_word": "A very common word hidden inside",
    "personal_info": "Your own username or email inside",
    "sequence": "A sequence like abc or 123",
    "keyboard_pattern": "A keyboard pattern like qwer",
    "repeats": "Repeated characters or pieces",
    "length": "A short password",
    "no_lowercase": "No lowercase letters",
    "no_uppercase": "No capital letters",
    "no_digits": "No numbers",
    "no_symbols": "No symbols or spaces",
}


# ---------- Scores and levels ----------
def clamp_score(score):
    """Keep a score inside 0 to 100."""
    return max(0, min(100, int(score)))


def get_risk_level(score):
    """Turn a score into a level name, for example 55 -> 'Medium'."""
    score = clamp_score(score)
    for name, lowest, highest in RISK_LEVELS:
        if lowest <= score <= highest:
            return name


def make_indicator(code, text, points, why=""):
    """One warning sign found by a scanner.

    code   short name, for example "no_https"
    text   what was found, in plain words
    points how much this adds to the risk score
    why    why this matters, in plain words
    """
    return {"code": code, "text": text, "points": points, "why": why}


def calculate_score(indicators):
    """The risk score is the total of all the points, limited to 0-100."""
    return clamp_score(sum(item["points"] for item in indicators))


def summarize_result(subject, score, level, sign_count, note=""):
    """A short written summary, for example: 'This link scored 50 out of 100, which is medium risk...'"""
    if sign_count == 0:
        found = "No warning signs were found."
    elif sign_count == 1:
        found = "We found 1 warning sign."
    else:
        found = f"We found {sign_count} warning signs."

    text = f"This {subject} scored {score} out of 100, which is {level.lower()} risk. "
    text += f"{LEVEL_SENTENCES[level]} {found}"
    if note:
        text += " " + note
    return text


# ---------- Explaining a score ----------
def points_of_problems(indicators):
    """The points of the real warning signs (good points and zero-point items are skipped)."""
    return [item["points"] for item in indicators if not item.get("good") and item.get("points", 0) > 0]


def explain_sum(indicators):
    """The sum behind a score, for example '15 + 20 + 15 = 50' or '30 + 25 + 40 + 20 = 115, limited to 100'."""
    points = points_of_problems(indicators)
    if not points:
        return "No points were added."
    total = sum(points)
    text = " + ".join(str(value) for value in points) + f" = {total}"
    if total > 100:
        text += ", limited to 100"
    return text


def category_of(code):
    """The kind of danger a warning sign belongs to ('other' if the code is not known)."""
    return RULE_CATEGORIES.get(code, "other")


def build_breakdown(indicators):
    """Where the points come from: a list of {key, label, points, width}, biggest first.

    `width` is the size of the bar in percent (the biggest kind has 100).
    """
    totals = {}
    for item in indicators:
        if item.get("good") or item.get("points", 0) <= 0:
            continue
        key = category_of(item.get("code"))
        totals[key] = totals.get(key, 0) + item["points"]

    if not totals:
        return []

    biggest = max(totals.values())
    parts = [
        {"key": key, "label": CATEGORY_LABELS[key], "points": points, "width": round(points * 100 / biggest)}
        for key, points in totals.items()
    ]
    parts.sort(key=lambda part: (-part["points"], CATEGORY_ORDER.index(part["key"])))
    return parts


def main_concern(breakdown):
    """The label of the kind of danger with the most points, or None."""
    if breakdown and breakdown[0]["key"] != "other":
        return breakdown[0]["label"]
    return None


# ---------- The list of all rules ----------
def get_rule_catalog():
    """Every rule of every scanner, read from the scanners' own tables.

    Returns a list of {title, scan_type, rules}. Each rule has: code, name, points_text,
    max_points, category, category_label, why. The scanners are imported here (not at
    the top of the file) because the scanners import this file.
    """
    from services import email_analyzer, password_analyzer, scam_detector, url_scanner

    scanners = [
        ("URL scanner", "url", url_scanner),
        ("Email analyzer", "email", email_analyzer),
        ("Scam detector", "scam", scam_detector),
        ("Password check", "password", password_analyzer),
    ]

    catalog = []
    for title, scan_type, module in scanners:
        rules = []
        for code, points in module.POINTS.items():
            rules.append({"code": code, "points_text": str(points), "max_points": points})

        if scan_type == "password":
            # The length rule has graded points (short passwords get more)
            length_points = [points for _, points in module.LENGTH_POINTS]
            rules.append({
                "code": "length",
                "points_text": f"{min(length_points)} to {max(length_points)}",
                "max_points": max(length_points),
            })

        for rule in rules:
            code = rule["code"]
            rule["name"] = RULE_NAMES.get(code, code)
            rule["category"] = category_of(code)
            rule["category_label"] = CATEGORY_LABELS[rule["category"]]
            rule["why"] = module.WHY.get(code, "")

        rules.sort(key=lambda rule: (-rule["max_points"], rule["name"]))
        catalog.append({"title": title, "scan_type": scan_type, "rules": rules})
    return catalog
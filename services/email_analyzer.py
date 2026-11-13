"""Email analyzer: reads the TEXT of an email and looks for phishing warning signs.

It never opens links or attachments and never sends anything. It is rule-based
(word lists and patterns), not AI. Links inside the email are checked with the
URL scanner from Phase 3. The score is the total of the points of the signs found.
"""
import re
from email.utils import parseaddr

from services.risk_engine import (
    calculate_score,
    get_risk_level,
    make_indicator,
    summarize_result,
)
from services.url_scanner import UrlError, find_brand_impersonation, scan_url, split_host

MIN_EMAIL_LENGTH = 15
MAX_EMAIL_LENGTH = 20000
MAX_LINKS_CHECKED = 10    # only the first links are checked
MAX_DETAILS_SHOWN = 5     # links listed under a warning sign

# ---------- The rules: how many points each warning sign adds ----------
POINTS = {
    "brand_impersonation": 30,
    "credentials": 25,
    "financial": 25,
    "suspicious_links": 25,   # at least one link scored Medium or higher in the URL scanner
    "reward_scam": 20,
    "risky_attachment": 20,
    "urgency": 15,
    "threats": 15,
    "account_verification": 15,
    "reply_to_mismatch": 15,
    "social_engineering": 15,
    "generic_greeting": 10,
    "risky_links": 10,        # the worst link scored Low
}

# A link needs this score for "suspicious_links", or this score for "risky_links"
SUSPICIOUS_LINK_SCORE = 41
RISKY_LINK_SCORE = 21

# ---------- Word lists (all lower case) ----------
URGENCY_PHRASES = [
    "urgent", "urgently", "immediately", "right away", "act now", "act fast",
    "within 24 hours", "within 48 hours", "within 12 hours", "within 2 hours",
    "as soon as possible", "asap", "last chance", "final notice", "final warning",
    "expires today", "expires soon", "limited time", "today only", "respond now",
    "hurry", "time is running out",
]

THREAT_PHRASES = [
    "will be suspended", "will be closed", "will be blocked", "will be terminated",
    "will be deactivated", "will be disabled", "will be deleted", "will be cancelled",
    "has been suspended", "has been locked", "has been blocked", "has been limited",
    "is blocked", "is suspended", "legal action", "police", "arrest", "penalty",
    "court", "lose access", "permanently closed", "permanently deleted",
    "permanently suspended",
]

VERIFICATION_PHRASES = [
    "verify your account", "verify your identity", "verify your email",
    "verify your details", "confirm your account", "confirm your identity",
    "validate your account", "update your account", "update your details",
    "update your information", "update your payment", "unusual activity",
    "suspicious activity", "suspicious login", "unauthorized login",
    "unauthorised login", "unauthorized access", "security alert",
    "reactivate your account", "re-activate your account", "kyc",
]

REWARD_PHRASES = [
    "you have won", "you've won", "you are a winner", "dear winner", "lottery",
    "lucky draw", "jackpot", "cash prize", "prize money", "claim your prize",
    "claim your reward", "claim your refund", "tax refund", "free gift",
    "you have been selected", "you are selected", "inheritance",
]

SOCIAL_PHRASES = [
    "keep this confidential", "keep this secret", "keep it secret",
    "do not tell anyone", "don't tell anyone", "do not discuss", "between us",
    "i need a favor", "i need a favour", "are you available", "i am in a meeting",
    "i'm in a meeting", "can't talk", "cannot talk", "do not call", "don't call",
    "personal request", "reply as soon as you see",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear member", "dear client",
    "dear valued customer", "dear valued member", "dear account holder",
    "dear sir or madam", "dear sir/madam", "dear friend", "dear beneficiary",
    "dear email owner",
]

FINANCIAL_PHRASES = [
    "gift card", "gift cards", "western union", "moneygram", "wire transfer",
    "bitcoin", "cryptocurrency", "processing fee", "advance fee",
    "registration fee", "release fee", "bank details", "bank account details",
    "card details", "credit card number",
]

# "send money", "pay a small fee", "transfer the amount" ...
FINANCIAL_PATTERN = re.compile(
    r"\b(?:send|transfer|wire|pay|deposit|remit)\b(?:\W+\w+){0,3}?\W+"
    r"(?:money|funds|fee|fees|tax|charges|amount)\b"
)

# "enter your password", "share the OTP", "confirm your PIN" ...
SECRET_WORDS = (
    r"(?:password|passcode|pin|otp|one[- ]time (?:password|passcode|code|pin)|cvv|"
    r"card number|card details|security code|login details|login credentials|"
    r"credentials|net ?banking (?:id|password|details)|atm pin|upi pin)"
)
ASK_VERBS = (
    r"(?:enter|send|share|provide|give|tell|confirm|verify|submit|type|"
    r"reply with|reveal|update|re-?enter|supply)"
)
CREDENTIAL_PATTERN = re.compile(rf"\b{ASK_VERBS}\b(?:\W+\w+){{0,4}}?\W+{SECRET_WORDS}\b")

# Words just before a match that turn it into advice ("never share your OTP")
NEGATIONS = ("do not", "don't", "never", "not ", "no one", "nobody", "avoid", "without")

MACRO_PHRASES = ["enable macros", "enable content", "enable editing"]
ATTACHMENT_PATTERN = re.compile(
    r"(?<![\w@/.-])[\w-]+(?:\.[\w-]+)*\.(?:exe|scr|js|vbs|bat|cmd|msi|jar|iso|"
    r"docm|xlsm|pptm|zip|rar|html?)(?![\w@-])"
)

LINK_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)

HEADER_LINE = re.compile(r"^([A-Za-z][A-Za-z-]*):[ \t]*(.*)$")
KNOWN_HEADERS = {
    "from", "to", "cc", "bcc", "subject", "reply-to", "date", "return-path",
    "received", "message-id", "sender",
}

# ---------- Texts shown to the user ----------
WHY = {
    "brand_impersonation": "The sender name or address uses the name of a well-known company, but the email does not come from that company.",
    "credentials": "Real companies never ask you to type or send your password, PIN, OTP or card details in an email.",
    "financial": "Scammers ask for money, fees or gift cards because they are hard to trace and hard to get back.",
    "suspicious_links": "Phishing emails lead you to fake websites. The link checker found strong warning signs in a link.",
    "risky_links": "The link checker found some warning signs in a link, so be careful before opening it.",
    "reward_scam": "Prize and refund emails are a very common trick to get your details or a fee.",
    "risky_attachment": "Files like .exe or .scr, and macro documents, can install harmful software. This check cannot open them.",
    "urgency": "Scammers rush you so you do not stop to think or check.",
    "threats": "Threats about closing your account or legal trouble are used to scare people into acting.",
    "account_verification": "Fake 'verify your account' emails are the most common way to steal logins.",
    "reply_to_mismatch": "When replies go to a different address than the sender, the real sender may be hiding.",
    "social_engineering": "Scammers ask for secrecy or a quick favour so you do not check with anyone.",
    "generic_greeting": "Real companies usually use your name. 'Dear customer' is a sign of a mass email.",
}

ADVICE_BY_CODE = {
    "brand_impersonation": "Contact the company using a phone number or website you already know, not the details in the email.",
    "credentials": "Never send passwords, PINs, OTPs or card details by email. Real companies do not ask for them this way.",
    "financial": "Do not send money, gift cards or bank details because of an email. Confirm the request by phone first.",
    "suspicious_links": "Do not click the links. Open the company's website by typing its address yourself.",
    "risky_links": "Do not click links in this email until you are sure who sent it.",
    "reward_scam": "You cannot win a contest you did not enter. Ignore prize and refund emails like this.",
    "risky_attachment": "Do not open the attachment and do not enable macros.",
    "urgency": "Slow down. A real company will not mind if you check first.",
    "threats": "Do not act on threats in an email. Check your account by opening the official app or website yourself.",
    "account_verification": "Do not verify your account through an email link. Log in through the official app or website.",
    "reply_to_mismatch": "Do not reply to this email. If you must reply, write a new email to an address you trust.",
    "social_engineering": "Check the request with the person in another way, for example by phone.",
    "generic_greeting": "Be careful with emails that do not use your name.",
}

ADVICE_BY_LEVEL = {
    "Safe": [
        "No strong warning signs were found, but this check only reads the text. "
        "If the email asks for money or secrets, check it another way.",
    ],
    "Low": [
        "Be careful with this email. Do not click links or open attachments unless you are sure who sent it.",
        "If it says it is from a company, open the company's website by typing the address yourself.",
    ],
    "Medium": [
        "Do not click links or open attachments in this email.",
        "Do not reply with passwords, OTPs or card details.",
        "Contact the sender using a phone number or website you already trust, not the ones in the email.",
    ],
    "High": [
        "Do not click any link or open any attachment.",
        "Do not reply, and do not send any money, codes or personal details.",
        "If you already clicked and typed a password, change that password now and turn on two-step verification.",
        "If you shared bank or card details, call your bank right away.",
        "Report the email as phishing in your email app (or to your organisation's IT team), then delete it.",
    ],
}
ADVICE_BY_LEVEL["Critical"] = ADVICE_BY_LEVEL["High"]

SCAN_NOTE = (
    "The checker only reads the text of the email. It never opens links or attachments "
    "and sends nothing, so a low score does not prove an email is safe."
)
NO_SENDER_NOTE = (
    "No From line was included, so the sender could not be checked. "
    "Paste the From, Reply-To and Subject lines too for a better check."
)


class EmailError(ValueError):
    """The text is not an email we can check. The message is safe to show to the user."""


# ---------- Step 1: read and clean the email ----------
def clean_email_text(raw_text):
    """Check the pasted text. Raises EmailError if it cannot be checked."""
    text = (raw_text or "").strip()
    if not text:
        raise EmailError("Please paste the email you want to check.")
    if len(text) < MIN_EMAIL_LENGTH:
        raise EmailError("That is too short to be a whole email. Please paste the full email.")
    if len(text) > MAX_EMAIL_LENGTH:
        raise EmailError(f"That email is too long. The limit is {MAX_EMAIL_LENGTH:,} characters.")
    # Remove hidden control characters but keep line breaks and tabs
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)


def split_email(text):
    """Split pasted text into (headers, body).

    Headers are lines like "From: ..." at the top. If the text does not start with
    a header block, there are no headers and the whole text is the body.
    """
    lines = text.splitlines()
    headers = {}
    last = None
    index = 0

    while index < len(lines) and lines[index].strip():
        line = lines[index]
        match = HEADER_LINE.match(line)
        if match:
            last = match.group(1).lower()
            headers.setdefault(last, match.group(2).strip())
        elif line[0] in " \t" and last:  # a long header continued on the next line
            headers[last] += " " + line.strip()
        else:
            return {}, text
        index += 1

    if not KNOWN_HEADERS & set(headers):
        return {}, text
    return headers, "\n".join(lines[index + 1:])


def normalize(text):
    """Lower case, straight quotes and single spaces, so phrases are easy to find."""
    for fancy, plain in (("\u2019", "'"), ("\u2018", "'"), ("\u201c", '"'), ("\u201d", '"')):
        text = text.replace(fancy, plain)
    return re.sub(r"\s+", " ", text.lower())


def build_target(subject, sender_address):
    """The short label saved with the scan. The email text itself is never saved."""
    subject = re.sub(r"\s+", " ", subject).strip()[:120]
    label = f"Email: {subject}" if subject else "Email (no subject)"
    if sender_address:
        label += f" (from {sender_address[:100]})"
    return label


# ---------- Step 2: small helper checks ----------
def find_phrases(text, phrases):
    """The phrases from the list that appear in the text, as whole words."""
    return [
        phrase for phrase in phrases
        if re.search(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", text)
    ]


def find_secret_request(text):
    """A request for a password, PIN, OTP or card details, or None.

    "enter your password" counts. "never share your OTP" does not: that is advice.
    """
    for match in CREDENTIAL_PATTERN.finditer(text):
        before = text[max(0, match.start() - 40):match.start()]
        if not any(word in before for word in NEGATIONS):
            return match.group(0)
    return None


def find_financial_request(text):
    """Words that ask for money, fees or gift cards."""
    found = find_phrases(text, FINANCIAL_PHRASES)
    match = FINANCIAL_PATTERN.search(text)
    if match and not any(phrase in match.group(0) for phrase in found):
        found.append(match.group(0))
    return found


def find_links(body):
    """The web addresses in the email, without repeats, in order."""
    links = []
    for match in LINK_PATTERN.finditer(body):
        link = match.group(0).rstrip(".,;:!?")
        if link.lower().startswith("www."):
            link = "https://" + link  # no http:// was typed, so do not punish a missing HTTPS
        if link not in links:
            links.append(link)
    return links


def check_links(links):
    """Check each link with the URL scanner. Returns a list of {url, score, level}."""
    results = []
    for link in links[:MAX_LINKS_CHECKED]:
        try:
            result = scan_url(link)
        except UrlError:
            continue  # not a usable link, skip it
        results.append({"url": link, "score": result["risk_score"], "level": result["risk_level"]})
    return results


def describe_link(item):
    return f"{item['url'][:120]} (score {item['score']}, {item['level']})"


def read_sender(headers):
    """Sender name, address and domain from the From line (empty text if missing)."""
    name, address = parseaddr(headers.get("from", ""))
    domain = address.rsplit("@", 1)[1].strip().lower() if "@" in address else ""
    return {"name": name.strip(), "address": address.strip(), "domain": domain}


def main_domain_of(domain):
    return split_host(domain)[1] if domain else ""


# ---------- Step 3: find the warning signs ----------
def find_warning_signs(headers, subject, body):
    """Return (signs, links_checked). Each sign is a dictionary made by make_indicator()."""
    signs = []

    def add(code, text, details=None):
        sign = make_indicator(code, text, POINTS[code], WHY[code])
        if details:
            sign["details"] = details
        signs.append(sign)

    sender = read_sender(headers)
    text = normalize(subject + "\n" + body)

    # Sender checks (only possible if a From line was pasted)
    if sender["domain"]:
        sender_main = main_domain_of(sender["domain"])
        name_and_address = sender["name"].lower().replace(" ", ".") + "@" + sender["domain"]
        brand = find_brand_impersonation(name_and_address, sender_main)
        if brand:
            add("brand_impersonation",
                f"The sender uses the name '{brand}', but the email comes from {sender['domain']}")

        _, reply_address = parseaddr(headers.get("reply-to", ""))
        reply_domain = reply_address.rsplit("@", 1)[1].strip().lower() if "@" in reply_address else ""
        if reply_domain and main_domain_of(reply_domain) != sender_main:
            add("reply_to_mismatch",
                f"Replies go to {reply_domain}, not to the sender's own domain ({sender['domain']})")

    # What the email asks for
    secret = find_secret_request(text)
    if secret:
        add("credentials", f"Asks for secret details: \"{secret}\"")

    money = find_financial_request(text)
    if money:
        add("financial", "Asks for money or payment details: " + ", ".join(money[:4]))

    # Words that push, scare or tempt
    for code, phrases, label in (
        ("urgency", URGENCY_PHRASES, "Pushes you to act quickly"),
        ("threats", THREAT_PHRASES, "Threatens you"),
        ("account_verification", VERIFICATION_PHRASES, "Asks you to verify or update your account"),
        ("reward_scam", REWARD_PHRASES, "Offers a prize or refund"),
        ("social_engineering", SOCIAL_PHRASES, "Asks for secrecy or a quick favour"),
        ("generic_greeting", GENERIC_GREETINGS, "Uses a generic greeting"),
    ):
        found = find_phrases(text, phrases)
        if found:
            add(code, f"{label}: " + ", ".join(found[:4]))

    # Links, checked with the URL scanner
    links = find_links(body)
    checked = check_links(links)
    if checked:
        worst = max(item["score"] for item in checked)
        dangerous = [item for item in checked if item["score"] >= RISKY_LINK_SCORE]
        details = [describe_link(item) for item in dangerous[:MAX_DETAILS_SHOWN]]
        if worst >= SUSPICIOUS_LINK_SCORE:
            add("suspicious_links", "A link in the email looks dangerous", details)
        elif worst >= RISKY_LINK_SCORE:
            add("risky_links", "A link in the email has some warning signs", details)

    # Attachments (we only see the names written in the text, never the files)
    text_without_links = LINK_PATTERN.sub(" ", body)
    files = [match.group(0) for match in ATTACHMENT_PATTERN.finditer(text_without_links.lower())]
    macros = find_phrases(text, MACRO_PHRASES)
    if files or macros:
        add("risky_attachment", "Mentions a risky file or asks you to enable macros: " + ", ".join((files + macros)[:4]))

    return signs, len(checked)


# ---------- Step 4: advice and the final result ----------
def get_recommendations(risk_level, codes):
    """Advice for the user: general advice for the level, then advice for each warning sign."""
    advice = list(ADVICE_BY_LEVEL.get(risk_level, []))
    for code in codes:
        line = ADVICE_BY_CODE.get(code)
        if line and line not in advice:
            advice.append(line)
    return advice


def analyze_email(raw_text):
    """Check one email and return the whole result. Raises EmailError for unusable text."""
    text = clean_email_text(raw_text)
    headers, body = split_email(text)
    subject = headers.get("subject", "")
    sender = read_sender(headers)

    indicators, links_checked = find_warning_signs(headers, subject, body)
    indicators.sort(key=lambda item: item["points"], reverse=True)

    score = calculate_score(indicators)
    level = get_risk_level(score)

    note = SCAN_NOTE if sender["address"] else NO_SENDER_NOTE + " " + SCAN_NOTE
    return {
        "target": build_target(subject, sender["address"]),
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "explanation": summarize_result("email", score, level, len(indicators), note),
        "recommendations": get_recommendations(level, [item["code"] for item in indicators]),
        "sender": sender,
        "links_checked": links_checked,
    }
"""The scanner pages: URL scanner, email analyzer, scam message detector and password check,
plus the result page and the "How scoring works" page."""
from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from models.scan import Scan
from services import email_analyzer, password_analyzer, risk_engine, scam_detector, url_scanner
from services.scan_service import save_scan
from utils.decorators import login_required

scanner_bp = Blueprint("scanner", __name__, url_prefix="/scan")

RECENT_LIMIT = 5

# Each scan type gives its own advice. Scan types without an entry show no advice.
RECOMMENDERS = {
    "url": url_scanner.get_recommendations,
    "email": email_analyzer.get_recommendations,
    "scam": scam_detector.get_recommendations,
    "password": password_analyzer.get_recommendations,
}


def get_recent_scans(scan_type):
    """The newest scans of one type for the logged-in user."""
    return (
        Scan.query.filter_by(user_id=g.user.id, scan_type=scan_type)
        .order_by(Scan.created_at.desc())
        .limit(RECENT_LIMIT)
        .all()
    )


@scanner_bp.route("/url", methods=["GET", "POST"])
@login_required
def url_scan():
    typed_url = ""

    if request.method == "POST":
        typed_url = request.form.get("url", "")
        try:
            result = url_scanner.scan_url(typed_url)
        except url_scanner.UrlError as error:
            flash(str(error), "danger")
        else:
            scan = save_scan(g.user.id, "url", result["url"], result)
            # Redirect after saving, so refreshing the page does not scan again
            return redirect(url_for("scanner.scan_detail", scan_id=scan.id))

    return render_template(
        "scanner/url.html",
        typed_url=typed_url[:url_scanner.MAX_URL_LENGTH],
        recent_scans=get_recent_scans("url"),
    )


@scanner_bp.route("/email", methods=["GET", "POST"])
@login_required
def email_scan():
    typed_text = ""

    if request.method == "POST":
        typed_text = request.form.get("email_text", "")
        try:
            result = email_analyzer.analyze_email(typed_text)
        except email_analyzer.EmailError as error:
            flash(str(error), "danger")
        else:
            # Only the subject, the sender and the result are saved, never the email text
            scan = save_scan(g.user.id, "email", result["target"], result)
            return redirect(url_for("scanner.scan_detail", scan_id=scan.id))

    return render_template(
        "scanner/email.html",
        typed_text=typed_text[:email_analyzer.MAX_EMAIL_LENGTH],
        recent_scans=get_recent_scans("email"),
    )


@scanner_bp.route("/scam", methods=["GET", "POST"])
@login_required
def scam_scan():
    typed_text = ""

    if request.method == "POST":
        typed_text = request.form.get("message_text", "")
        try:
            result = scam_detector.analyze_message(typed_text)
        except scam_detector.MessageError as error:
            flash(str(error), "danger")
        else:
            # Only a short label (long numbers hidden) and the result are saved, never the message
            scan = save_scan(g.user.id, "scam", result["target"], result)
            return redirect(url_for("scanner.scan_detail", scan_id=scan.id))

    return render_template(
        "scanner/scam.html",
        typed_text=typed_text[:scam_detector.MAX_MESSAGE_LENGTH],
        recent_scans=get_recent_scans("scam"),
    )


@scanner_bp.route("/password", methods=["GET", "POST"])
@login_required
def password_scan():
    if request.method == "POST":
        # The password lives only in this variable while it is checked.
        # It is never saved, never logged and never put back into the page.
        password = request.form.get("password", "")
        personal_words = [g.user.username, g.user.email.split("@")[0]]
        try:
            result = password_analyzer.analyze_password(password, personal_words)
        except password_analyzer.PasswordError as error:
            flash(str(error), "danger")
        else:
            scan = save_scan(g.user.id, "password", result["target"], result)
            return redirect(url_for("scanner.scan_detail", scan_id=scan.id))

    recent_checks = [
        {"scan": scan, "strength": password_analyzer.get_strength(scan.risk_score)}
        for scan in get_recent_scans("password")
    ]
    return render_template("scanner/password.html", recent_checks=recent_checks)


@scanner_bp.route("/scoring")
@login_required
def scoring_guide():
    """Explains the scoring: the levels and every rule of every scanner."""
    return render_template(
        "scanner/scoring.html",
        catalog=risk_engine.get_rule_catalog(),
        threat_min_score=risk_engine.THREAT_MIN_SCORE,
    )


@scanner_bp.route("/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    # Only the owner may open a scan. Anyone else gets "not found".
    scan = Scan.query.filter_by(id=scan_id, user_id=g.user.id).first_or_404()

    indicators = scan.indicators or []

    details = None
    if scan.scan_type == "url":
        try:
            details = url_scanner.describe_url(scan.target)
        except url_scanner.UrlError:
            details = None

    strength = None
    if scan.scan_type == "password":
        strength = password_analyzer.get_strength(scan.risk_score)

    # Where the points come from. A password has only one kind of danger, so it gets no "main concern".
    breakdown = risk_engine.build_breakdown(indicators)
    main_concern = None if scan.scan_type == "password" else risk_engine.main_concern(breakdown)

    recommender = RECOMMENDERS.get(scan.scan_type)
    recommendations = []
    if recommender:
        codes = [item.get("code") for item in indicators if not item.get("good")]
        recommendations = recommender(scan.risk_level, codes)

    return render_template(
        "scanner/result.html",
        scan=scan,
        indicators=indicators,
        details=details,
        strength=strength,
        breakdown=breakdown,
        main_concern=main_concern,
        sum_text=risk_engine.explain_sum(indicators),
        recommendations=recommendations,
    )
"""Tests for the risk engine: levels, scores, kinds of danger and the list of all rules."""
from services import email_analyzer, password_analyzer, scam_detector, url_scanner
from services.risk_engine import (
    CATEGORY_LABELS,
    RISK_LEVELS,
    RULE_CATEGORIES,
    RULE_NAMES,
    THREAT_MIN_SCORE,
    build_breakdown,
    calculate_score,
    category_of,
    clamp_score,
    explain_sum,
    get_risk_level,
    get_rule_catalog,
    main_concern,
    make_indicator,
    summarize_result,
)

SCANNERS = [url_scanner, email_analyzer, scam_detector, password_analyzer]


def sign(code, points, **extra):
    item = make_indicator(code, "text", points)
    item.update(extra)
    return item


# ---------- Levels and scores ----------

def test_level_boundaries():
    expected = {
        0: "Safe", 20: "Safe",
        21: "Low", 40: "Low",
        41: "Medium", 60: "Medium",
        61: "High", 80: "High",
        81: "Critical", 100: "Critical",
    }
    for score, level in expected.items():
        assert get_risk_level(score) == level


def test_the_levels_cover_every_score_from_0_to_100_without_gaps():
    assert RISK_LEVELS[0][1] == 0
    assert RISK_LEVELS[-1][2] == 100
    for (_, _, previous_high), (_, next_low, _) in zip(RISK_LEVELS, RISK_LEVELS[1:]):
        assert next_low == previous_high + 1
    for score in range(0, 101):
        assert get_risk_level(score) in ("Safe", "Low", "Medium", "High", "Critical")


def test_scores_outside_the_range_are_limited():
    assert clamp_score(-5) == 0
    assert clamp_score(250) == 100
    assert get_risk_level(-5) == "Safe"
    assert get_risk_level(250) == "Critical"


def test_threat_starts_at_medium():
    assert get_risk_level(THREAT_MIN_SCORE) == "Medium"
    assert get_risk_level(THREAT_MIN_SCORE - 1) == "Low"


def test_make_indicator_has_all_fields():
    item = make_indicator("no_https", "No HTTPS", 15, "Because of this")
    assert item == {"code": "no_https", "text": "No HTTPS", "points": 15, "why": "Because of this"}


def test_score_is_the_total_of_the_points_and_never_above_100():
    assert calculate_score([]) == 0
    assert calculate_score([make_indicator("a", "A", 15), make_indicator("b", "B", 20)]) == 35
    assert calculate_score([make_indicator("a", "A", 60), make_indicator("b", "B", 70)]) == 100


def test_summary_mentions_score_level_and_number_of_signs():
    text = summarize_result("link", 55, "Medium", 3)
    assert "55 out of 100" in text
    assert "medium risk" in text
    assert "3 warning signs" in text
    assert "1 warning sign." in summarize_result("link", 15, "Safe", 1)
    assert "No warning signs" in summarize_result("link", 0, "Safe", 0)
    assert summarize_result("link", 0, "Safe", 0, "Extra note.").endswith("Extra note.")


# ---------- Explaining a score ----------

def test_explain_sum_shows_the_addition():
    assert explain_sum([sign("a", 15), sign("b", 20), sign("c", 15)]) == "15 + 20 + 15 = 50"
    assert explain_sum([sign("a", 15)]) == "15 = 15"


def test_explain_sum_says_when_the_total_was_limited():
    assert explain_sum([sign("a", 60), sign("b", 50)]) == "60 + 50 = 110, limited to 100"
    assert explain_sum([sign("a", 60), sign("b", 40)]) == "60 + 40 = 100"


def test_explain_sum_skips_good_points_and_zero_points():
    items = [sign("a", 25), sign("b_ok", 0, good=True), sign("c", 0)]
    assert explain_sum(items) == "25 = 25"
    assert explain_sum([sign("b_ok", 0, good=True)]) == "No points were added."
    assert explain_sum([]) == "No points were added."


# ---------- Kinds of danger ----------

def test_breakdown_groups_the_points_by_kind_of_danger():
    items = [
        sign("otp_request", 30), sign("urgency", 15), sign("account_threats", 20),
        sign("suspicious_links", 25), sign("no_https", 15),
    ]
    parts = build_breakdown(items)
    by_key = {part["key"]: part["points"] for part in parts}
    assert by_key == {"credentials": 30, "pressure": 35, "links": 40}
    assert [part["key"] for part in parts] == ["links", "pressure", "credentials"]  # biggest first
    assert [part["width"] for part in parts] == [100, round(35 * 100 / 40), round(30 * 100 / 40)]
    assert parts[0]["label"] == CATEGORY_LABELS["links"]


def test_breakdown_points_add_up_to_the_points_of_the_signs():
    items = [sign("otp_request", 30), sign("brand_link_mismatch", 30), sign("urgency", 15), sign("shortened_link", 15)]
    assert sum(part["points"] for part in build_breakdown(items)) == 90


def test_equal_kinds_are_listed_in_a_fixed_order():
    parts = build_breakdown([sign("brand_link_mismatch", 30), sign("otp_request", 30)])
    assert [part["key"] for part in parts] == ["credentials", "impersonation"]


def test_breakdown_skips_good_points_and_puts_unknown_codes_under_other():
    parts = build_breakdown([sign("length_ok", 0, good=True), sign("something_new", 10), sign(None, 5)])
    assert [(part["key"], part["points"]) for part in parts] == [("other", 15)]
    assert build_breakdown([]) == []
    assert build_breakdown([sign("length_ok", 0, good=True)]) == []


def test_main_concern_is_the_biggest_kind_of_danger():
    parts = build_breakdown([sign("otp_request", 30), sign("urgency", 15)])
    assert main_concern(parts) == "Stealing logins or codes"
    assert main_concern([]) is None
    assert main_concern(build_breakdown([sign("something_new", 10)])) is None


def test_category_of_a_code():
    assert category_of("no_https") == "links"
    assert category_of("otp_request") == "credentials"
    assert category_of("common_password") == "password"
    assert category_of("not_a_rule") == "other"


# ---------- The rules of all scanners ----------

def test_the_catalog_has_every_rule_of_every_scanner():
    catalog = get_rule_catalog()
    assert [scanner["scan_type"] for scanner in catalog] == ["url", "email", "scam", "password"]
    for scanner, module in zip(catalog, SCANNERS):
        expected = len(module.POINTS) + (1 if scanner["scan_type"] == "password" else 0)  # the length rule
        assert len(scanner["rules"]) == expected


def test_every_rule_has_a_name_a_kind_of_danger_and_sensible_points():
    for scanner in get_rule_catalog():
        for rule in scanner["rules"]:
            assert rule["code"] in RULE_NAMES, rule["code"]
            assert rule["name"] == RULE_NAMES[rule["code"]]
            assert rule["code"] in RULE_CATEGORIES, rule["code"]
            assert rule["category"] != "other"
            assert 1 <= rule["max_points"] <= 100
            assert rule["points_text"]


def test_every_rule_has_an_explanation_and_advice_in_its_scanner():
    for module in SCANNERS:
        for code in module.POINTS:
            assert code in module.WHY, (module.__name__, code)
            assert code in module.ADVICE_BY_CODE, (module.__name__, code)


def test_rules_listed_in_more_than_one_scanner_have_the_same_points():
    """One policy: the same warning sign is worth the same in every scanner."""
    points_by_code = {}
    for module in SCANNERS:
        for code, points in module.POINTS.items():
            points_by_code.setdefault(code, set()).add(points)
    shared = {code: values for code, values in points_by_code.items() if len(values) > 1}
    assert shared == {}


def test_names_and_kinds_are_only_defined_for_real_rules():
    real_codes = {code for module in SCANNERS for code in module.POINTS} | {"length"}
    assert set(RULE_NAMES) == real_codes
    assert set(RULE_CATEGORIES) == real_codes


def test_the_password_length_rule_shows_its_range():
    password = [scanner for scanner in get_rule_catalog() if scanner["scan_type"] == "password"][0]
    length_rule = [rule for rule in password["rules"] if rule["code"] == "length"][0]
    assert length_rule["points_text"] == "5 to 45"
    assert length_rule["max_points"] == 45


def test_rules_are_listed_with_the_biggest_points_first():
    for scanner in get_rule_catalog():
        points = [rule["max_points"] for rule in scanner["rules"]]
        assert points == sorted(points, reverse=True)
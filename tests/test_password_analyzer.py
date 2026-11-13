"""Tests for the password analyzer. It needs no internet and no database."""
import json

import pytest

from services.password_analyzer import (
    MAX_PASSWORD_LENGTH,
    PasswordError,
    TARGET_LABEL,
    analyze_password,
    get_recommendations,
    get_strength,
    has_keyboard_pattern,
    has_repeats,
    is_common_password,
    length_points,
    sequence_share,
)

STRONG_PASSPHRASE = "lantern-river-mango-quiet-47"


def problems(password, personal_words=()):
    """The codes of the weaknesses found."""
    result = analyze_password(password, personal_words)
    return {item["code"] for item in result["indicators"] if not item.get("good")}


def good_points(password):
    result = analyze_password(password)
    return {item["code"] for item in result["indicators"] if item.get("good")}


# ---------- Whole passwords ----------

def test_a_very_common_password_is_weak_and_critical():
    result = analyze_password("password123")
    assert "common_password" in problems("password123")
    assert result["risk_score"] == 100
    assert result["risk_level"] == "Critical"
    assert result["strength"] == {"label": "Weak", "score": 0}


def test_a_long_passphrase_is_strong():
    result = analyze_password(STRONG_PASSPHRASE)
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Safe"
    assert result["strength"] == {"label": "Strong", "score": 100}
    assert problems(STRONG_PASSPHRASE) == set()


def test_a_medium_password_is_moderate():
    result = analyze_password("Tiger7Blue")
    assert problems("Tiger7Blue") == {"length", "no_symbols"}
    assert result["risk_score"] == 30  # 20 + 10
    assert result["strength"]["label"] == "Moderate"


def test_a_short_lowercase_password_is_weak():
    result = analyze_password("kzqmxwjd")
    assert problems("kzqmxwjd") == {"length", "no_uppercase", "no_digits", "no_symbols"}
    assert result["risk_score"] == 60  # 30 + 10 + 10 + 10
    assert result["strength"]["label"] == "Weak"


def test_score_is_the_total_of_the_points_and_never_above_100():
    for password in ("password", "Tiger7Blue", STRONG_PASSPHRASE, "aaaaaaaaaaaaaaaa", "kzqmxwjd"):
        result = analyze_password(password)
        total = sum(item["points"] for item in result["indicators"])
        assert result["risk_score"] == min(100, total)


def test_weaknesses_come_first_and_good_points_last():
    items = analyze_password("kP9$abc7Zq")["indicators"]
    points = [item["points"] for item in items]
    assert points == sorted(points, reverse=True)
    assert all(item.get("good") for item in items if item["points"] == 0)


# ---------- Length ----------

def test_points_for_each_length():
    expected = {1: 45, 5: 45, 6: 40, 7: 40, 8: 30, 9: 30, 10: 20, 11: 20, 12: 10, 13: 10, 14: 5, 15: 5, 16: 0, 40: 0}
    for length, points in expected.items():
        assert length_points(length) == points


def test_length_is_the_only_problem_for_a_mixed_password_without_patterns():
    pool = "kP9$zQ2#mW4&xL7!"
    expected = {5: 45, 7: 40, 9: 30, 11: 20, 13: 10, 15: 5, 16: 0}
    for length, points in expected.items():
        result = analyze_password(pool[:length])
        assert result["risk_score"] == points, length


def test_long_passwords_do_not_need_every_kind_of_character():
    assert problems("kzqmxwjdbhvnctgpfs") == set()
    assert "length_ok" in good_points("kzqmxwjdbhvnctgpfs")


# ---------- Common passwords ----------

def test_common_passwords_with_extras_are_still_common():
    assert is_common_password("password")
    assert is_common_password("PASSWORD")        # capital letters do not help
    assert is_common_password("P@ssw0rd")        # look-alike letters do not help
    assert is_common_password("Summer2024!")     # numbers and symbols at the end do not help
    assert is_common_password("iloveyou2024")
    assert not is_common_password(STRONG_PASSPHRASE)


def test_a_common_word_hidden_in_a_longer_password():
    assert problems("MyPasswordIsLong99") == {"common_word"}
    assert "common_password" not in problems("MyPasswordIsLong99")


# ---------- Patterns ----------

def test_sequences():
    assert sequence_share("kP9$abc7Zq") == pytest.approx(0.3)
    assert sequence_share("kP9$zQ2#mW4&") == 0.0
    assert "sequence" in problems("kP9$abc7Zq")
    assert "sequence" in problems("xy4321Lm$k")  # going down counts too


def test_a_password_that_is_mostly_a_sequence_is_much_worse():
    assert sequence_share("1234567890123456") >= 0.5
    assert problems("1234567890123456") == {"mostly_sequence"}
    assert analyze_password("1234567890123456")["risk_score"] == 60


def test_keyboard_patterns():
    assert has_keyboard_pattern("kP9#qwerLm2")
    assert has_keyboard_pattern("kP9#rewqLm2")  # backwards
    assert has_keyboard_pattern("xASDFx")
    assert not has_keyboard_pattern("kP9$zQ2#mW4&")
    assert "keyboard_pattern" in problems("kP9#qwerLm2")


def test_repeats():
    assert has_repeats("kP9$aaaZm2#")
    assert has_repeats("kP9$abab$Zq")
    assert has_repeats("xyzxyz")
    assert not has_repeats("kP9$zQ2#mW4&")
    assert "repeats" in problems("kP9$aaaZm2#")


def test_very_few_different_characters():
    assert "few_unique" in problems("ababababab")
    assert "few_unique" in problems("aaaaaaaaaaaaaaaa")
    assert "few_unique" not in problems("abcd")
    assert "few_unique" not in problems("Tiger7Blue")


# ---------- Kinds of characters ----------

def test_missing_kinds_of_characters_in_a_short_password():
    assert {"no_lowercase", "no_uppercase", "no_symbols"} <= problems("12345678")
    assert "no_digits" in problems("Tiger!Blue")
    assert "no_symbols" in problems("Tiger7Blue")
    assert "no_uppercase" in problems("tiger7blue!")


def test_spaces_and_other_alphabets_count_as_symbols():
    assert "no_symbols" not in problems("two words 9X")
    assert "no_symbols" not in problems("p\u00e4ssw\u00f6rd9X")


def test_good_points_are_listed():
    good = good_points("kP9$zQ2#mW4&xL7!")
    assert {"length_ok", "lowercase_ok", "uppercase_ok", "digits_ok", "symbols_ok",
            "common_password_ok", "sequence_ok", "keyboard_pattern_ok", "repeats_ok"} <= good


# ---------- The user's own words ----------

def test_username_or_email_name_inside_the_password():
    assert "personal_info" in problems("owner-Lantern-River-9", ["owner"])
    assert "personal_info" in problems("OWNER-Lantern-River-9", ["owner"])
    assert "personal_info" not in problems("owner-Lantern-River-9")
    assert "personal_info" not in problems("owner-Lantern-River-9", ["al", "", None])
    assert "personal_info" not in problems("lantern-River-Mango-9", ["owner"])


# ---------- Privacy ----------

def test_the_result_never_contains_the_password():
    for password in ("Zx9-Unique-Candidate-7731!", "password123", "hunter2hunter2", "Tiger7Blue", "Qq1!Qq1!Qq1!"):
        result = analyze_password(password, ["owner"])
        everything = json.dumps(result) + repr(result)
        assert password not in everything
        assert password.lower() not in everything.lower()


def test_no_finding_mentions_the_exact_length_or_a_part_of_the_password():
    result = analyze_password("Zx9-Tiger-Candidate-7731!")
    text = " ".join(item["text"] + item["why"] for item in result["indicators"])
    for piece in ("Zx9", "Tiger", "Candidate", "7731"):
        assert piece not in text
    assert "25 characters" not in text


def test_the_label_saved_with_the_scan_does_not_describe_the_password():
    assert analyze_password("password123")["target"] == TARGET_LABEL
    assert analyze_password(STRONG_PASSPHRASE)["target"] == TARGET_LABEL
    assert "not stored" in TARGET_LABEL


def test_the_explanation_says_the_password_was_not_saved():
    text = analyze_password("password123")["explanation"]
    assert "not saved" in text
    assert "not written to any log" in text
    assert "including the AI" in text


# ---------- Bad input ----------

def test_unusable_input_is_refused_without_repeating_the_password():
    for value in (None, "", 12345):
        with pytest.raises(PasswordError) as info:
            analyze_password(value)
        assert str(info.value)

    too_long = "Zx9-" * 40
    with pytest.raises(PasswordError) as info:
        analyze_password(too_long)
    assert str(MAX_PASSWORD_LENGTH) in str(info.value)
    assert too_long not in str(info.value)


def test_exactly_the_longest_password_is_accepted():
    assert analyze_password("k" * MAX_PASSWORD_LENGTH)["risk_score"] >= 0


def test_spaces_are_part_of_the_password_and_are_not_removed():
    assert analyze_password("        ")["risk_score"] > 0  # eight spaces are checked, not refused
    assert "no_symbols" not in problems("two words 9X")


def test_unusual_characters_do_not_break_the_checker():
    for password in ("\u00fcn\u00efc\u00f6d\u00e9 \u2713", "\U0001F600\U0001F600\U0001F600\U0001F600", "tab\tchar", "a\nb\nc\nd"):
        assert analyze_password(password)["risk_level"]


# ---------- Strength label, advice and summary ----------

def test_strength_label_follows_the_risk_level():
    assert get_strength(0) == {"label": "Strong", "score": 100}
    assert get_strength(20) == {"label": "Strong", "score": 80}
    assert get_strength(21) == {"label": "Moderate", "score": 79}
    assert get_strength(40) == {"label": "Moderate", "score": 60}
    assert get_strength(41) == {"label": "Weak", "score": 59}
    assert get_strength(100) == {"label": "Weak", "score": 0}


def test_recommendations():
    weak = get_recommendations("Critical", ["common_password", "common_password", "unknown_code"])
    assert any("Do not use this password for anything important" in line for line in weak)
    assert any("not on lists of common passwords" in line for line in weak)
    assert len(weak) == len(set(weak))  # no repeated lines
    assert any("password manager" in line for line in get_recommendations("Safe", []))
    assert any("longer one is safer" in line for line in get_recommendations("Low", []))


def test_result_has_everything_the_page_needs():
    result = analyze_password("password123")
    assert result["recommendations"]
    assert "weak" in result["explanation"]
    assert "100 out of 100" in result["explanation"]
    for item in result["indicators"]:
        if not item.get("good"):
            assert item["why"]
"""Tests for the URL scanner. It only reads text, so these tests need no internet and no database."""
import pytest

from services.url_scanner import (
    UrlError,
    describe_url,
    get_recommendations,
    scan_url,
    split_host,
)


def codes(url):
    """The codes of the warning signs found in a link."""
    return {item["code"] for item in scan_url(url)["indicators"]}


# ---------- Whole results ----------

def test_clean_https_link_has_no_warning_signs():
    result = scan_url("https://docs.python.org/3/")
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Safe"
    assert result["indicators"] == []


def test_http_only_link_loses_points_but_stays_safe():
    result = scan_url("http://example.org/")
    assert result["risk_score"] == 15
    assert result["risk_level"] == "Safe"
    assert codes("http://example.org/") == {"no_https"}


def test_ip_address_link_scores_medium():
    result = scan_url("http://192.168.10.25/login/verify")
    assert codes("http://192.168.10.25/login/verify") == {"no_https", "ip_address", "keywords"}
    assert result["risk_score"] == 50  # 15 + 20 + 15
    assert result["risk_level"] == "Medium"


def test_brand_name_on_the_wrong_website_scores_high():
    result = scan_url("http://paypal.com@account-verify.example/login/update")
    assert codes("http://paypal.com@account-verify.example/login/update") == {
        "no_https", "keywords", "at_sign", "brand_impersonation",
    }
    assert result["risk_score"] == 70  # 15 + 15 + 10 + 30
    assert result["risk_level"] == "High"


def test_worst_case_is_capped_at_100():
    url = "http://paypal.com@a.b.c.xn--80ak6aa92e.xyz/login/" + "a" * 60
    result = scan_url(url)
    assert codes(url) == {
        "no_https", "keywords", "subdomains", "at_sign",
        "lookalike_chars", "risky_tld", "long_url", "brand_impersonation",
    }
    assert sum(item["points"] for item in result["indicators"]) == 110
    assert result["risk_score"] == 100  # 110 points, limited to 100
    assert result["risk_level"] == "Critical"


def test_score_always_equals_the_total_of_the_points():
    urls = [
        "https://example.com/",
        "http://bit.ly/abc",
        "http://a.b.c.example.xyz/login",
        "https://www.bbc.co.uk/news",
    ]
    for url in urls:
        result = scan_url(url)
        total = sum(item["points"] for item in result["indicators"])
        assert result["risk_score"] == min(100, total)


def test_warning_signs_are_listed_biggest_first():
    points = [item["points"] for item in scan_url("http://192.168.10.25/login/verify")["indicators"]]
    assert points == sorted(points, reverse=True)


# ---------- Single rules ----------

def test_ipv6_decimal_and_hex_addresses_count_as_ip_numbers():
    assert "ip_address" in codes("https://[::1]/")
    assert "ip_address" in codes("https://3232235777/")
    assert "ip_address" in codes("https://0xC0A80101/")
    assert "ip_address" not in codes("https://example.com/")


def test_suspicious_words_are_counted_once():
    result = scan_url("https://example.com/login/verify/account")
    keyword_signs = [item for item in result["indicators"] if item["code"] == "keywords"]
    assert len(keyword_signs) == 1
    assert keyword_signs[0]["points"] == 15
    for word in ("login", "verify", "account"):
        assert word in keyword_signs[0]["text"]


def test_hyphens_do_not_hide_suspicious_words():
    assert "keywords" in codes("https://example.com/sign-in")
    assert "keywords" in codes("https://secure-log-in.example.com/")


def test_too_many_subdomains():
    assert "subdomains" in codes("https://a.b.c.example.com/")
    assert "subdomains" not in codes("https://www.mail.example.com/")
    assert "subdomains" not in codes("https://www.bbc.co.uk/")
    assert "subdomains" in codes("https://a.b.c.bbc.co.uk/")


def test_at_sign_hides_the_real_website():
    assert "at_sign" in codes("https://example.com@evil.example/")
    assert describe_url("https://example.com@evil.example/")["host"] == "evil.example"


def test_lookalike_letters():
    assert "lookalike_chars" in codes("https://xn--pple-43d.example/")
    assert "lookalike_chars" in codes("https://\u0430pple.example/")  # Cyrillic a
    assert "lookalike_chars" not in codes("https://apple.example/")


def test_link_length_limit():
    base = "https://example.com/"
    assert "long_url" not in codes(base + "a" * (100 - len(base)))
    assert "long_url" in codes(base + "a" * (101 - len(base)))


def test_link_shorteners():
    assert "shortener" in codes("https://bit.ly/abc")
    assert "shortener" not in codes("https://example.com/bit.ly")


def test_risky_website_endings():
    assert "risky_tld" in codes("https://holiday-offers.xyz/")
    assert "risky_tld" not in codes("https://holiday-offers.com/")


def test_brand_names_on_real_and_fake_websites():
    assert "brand_impersonation" not in codes("https://www.paypal.com/")
    assert "brand_impersonation" not in codes("https://mail.google.co.in/")
    assert "brand_impersonation" in codes("https://paypal.com.account-verify.example/")
    assert "brand_impersonation" in codes("https://paypal-support.example/")
    assert "brand_impersonation" in codes("https://paypa1.example/")  # 1 instead of l


def test_short_brand_names_must_be_a_whole_word():
    assert "brand_impersonation" not in codes("https://classbiz.example/")
    assert "brand_impersonation" in codes("https://sbi.example/")
    assert "brand_impersonation" in codes("https://sbi-login.example/")


# ---------- Bad input ----------

def test_unusable_text_is_refused_with_a_clear_message():
    bad_inputs = [
        "",
        "   ",
        "example.com",
        "ftp://example.com/file",
        "http://",
        "http://exa mple.com",
        "http://example.com/\nsecond-line",
        "http://[::1",
        "http://example.com:99999/",
        "javascript:alert(1)",
        "https://example.com/" + "a" * 2000,
    ]
    for text in bad_inputs:
        with pytest.raises(UrlError) as info:
            scan_url(text)
        assert str(info.value)


def test_error_messages_explain_what_to_fix():
    with pytest.raises(UrlError) as info:
        scan_url("example.com")
    assert "http://" in str(info.value)
    with pytest.raises(UrlError) as info:
        scan_url("ftp://example.com")
    assert "Only http" in str(info.value)


def test_none_is_refused():
    with pytest.raises(UrlError):
        scan_url(None)


# ---------- Details, advice and summary ----------

def test_split_host():
    assert split_host("www.example.com") == (["www"], "example.com", "com")
    assert split_host("a.b.example.co.in") == (["a", "b"], "example.co.in", "co.in")
    assert split_host("example.com") == ([], "example.com", "com")
    assert split_host("localhost") == ([], "localhost", "")


def test_link_details():
    details = describe_url("https://a.b.example.co.in:8443/x")
    assert details["protocol"] == "https"
    assert details["host"] == "a.b.example.co.in"
    assert details["main_domain"] == "example.co.in"
    assert details["ending"] == "co.in"
    assert details["subdomains"] == ["a", "b"]
    assert details["port"] == 8443
    assert details["is_ip"] is False

    ip_details = describe_url("http://192.168.10.25/")
    assert ip_details["is_ip"] is True
    assert ip_details["main_domain"] == ""
    assert ip_details["port"] is None


def test_recommendations():
    assert get_recommendations("Safe", [])
    assert any("Do not open this link" in line for line in get_recommendations("High", []))
    medium = get_recommendations("Medium", ["no_https", "no_https", "unknown_code"])
    assert any("HTTPS" in line for line in medium)
    assert len(medium) == len(set(medium))  # no repeated lines


def test_result_has_everything_the_page_needs():
    result = scan_url("http://192.168.10.25/login/verify")
    assert result["url"] == "http://192.168.10.25/login/verify"
    assert "50 out of 100" in result["explanation"]
    assert "never opens the website" in result["explanation"]
    assert result["recommendations"]
    for item in result["indicators"]:
        assert item["why"]
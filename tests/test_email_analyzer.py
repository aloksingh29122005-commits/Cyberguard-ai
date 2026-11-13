"""Tests for the email analyzer. It only reads text, so these tests need no internet and no database."""
import pytest

from services.email_analyzer import (
    EmailError,
    analyze_email,
    build_target,
    find_secret_request,
    get_recommendations,
    split_email,
)

SAFE_EMAIL = """From: Priya Sharma <priya@example.org>
Subject: Notes from Friday's meeting

Hi team,

Here are the notes from Friday's meeting. The next meeting is on Tuesday at 10 am. Please send me any changes by Monday.

Thanks,
Priya"""

MEDIUM_EMAIL = """Subject: Congratulations, you have won!

Dear winner, you have won a cash prize in our lucky draw. To claim your reward, pay a small processing fee today."""

PHISHING_EMAIL = """From: "PayPal Support" <support@paypa1-secure.example>
Reply-To: helpdesk@gmail.com
Subject: URGENT: Your account will be suspended

Dear customer,

We noticed unusual activity on your account. You must verify your account within 24 hours or it will be suspended permanently.

Please confirm your password and OTP here: http://paypa1-secure.example/verify/login

Thank you,
Security Team"""


def codes(text):
    """The codes of the warning signs found in an email."""
    return {item["code"] for item in analyze_email(text)["indicators"]}


def body_codes(body):
    """Codes for an email that is only a body (no headers)."""
    return codes("Hello,\n\n" + body)


# ---------- Whole emails ----------

def test_normal_email_has_no_warning_signs():
    result = analyze_email(SAFE_EMAIL)
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Safe"
    assert result["indicators"] == []


def test_prize_email_scores_medium():
    result = analyze_email(MEDIUM_EMAIL)
    assert codes(MEDIUM_EMAIL) == {"financial", "reward_scam"}
    assert result["risk_score"] == 45  # 25 + 20
    assert result["risk_level"] == "Medium"


def test_classic_phishing_email_is_critical():
    result = analyze_email(PHISHING_EMAIL)
    assert codes(PHISHING_EMAIL) == {
        "brand_impersonation", "credentials", "suspicious_links", "reply_to_mismatch",
        "urgency", "threats", "account_verification", "generic_greeting",
    }
    total = sum(item["points"] for item in result["indicators"])
    assert total == 150
    assert result["risk_score"] == 100  # limited to 100
    assert result["risk_level"] == "Critical"


def test_score_always_equals_the_total_of_the_points():
    for text in (SAFE_EMAIL, MEDIUM_EMAIL, PHISHING_EMAIL):
        result = analyze_email(text)
        total = sum(item["points"] for item in result["indicators"])
        assert result["risk_score"] == min(100, total)


def test_warning_signs_are_listed_biggest_first():
    points = [item["points"] for item in analyze_email(PHISHING_EMAIL)["indicators"]]
    assert points == sorted(points, reverse=True)


# ---------- What the email asks for ----------

def test_requests_for_secret_details_are_found():
    assert "credentials" in body_codes("Please enter your password to continue.")
    assert "credentials" in body_codes("Kindly share the OTP you received on your phone.")
    assert "credentials" in body_codes("You must confirm your card number and CVV today.")


def test_advice_about_secret_details_is_not_a_request():
    assert "credentials" not in body_codes("Never share your OTP with anyone, even our staff.")
    assert "credentials" not in body_codes("We will never ask you to enter your password in an email.")
    assert "credentials" not in body_codes("Do not give your PIN to anybody.")
    assert "credentials" not in body_codes("Use the link to reset your password. Thanks for your help.")


def test_find_secret_request_returns_the_matching_words():
    assert find_secret_request("please enter your password now") == "enter your password"
    assert find_secret_request("never enter your password anywhere") is None


def test_requests_for_money_are_found():
    assert "financial" in body_codes("Please send money to this account.")
    assert "financial" in body_codes("You must pay a small fee to release the parcel.")
    assert "financial" in body_codes("Buy gift cards and send me the codes.")
    assert "financial" in body_codes("Send the amount by wire transfer.")
    assert "financial" not in body_codes("Thanks for the payment, see you on Monday.")


def test_financial_sign_does_not_repeat_the_same_words():
    text = analyze_email("Hello,\n\nPay a small processing fee today.")["indicators"][0]["text"]
    assert text.count("processing fee") == 1


# ---------- Pressure, threats and tempting offers ----------

def test_urgent_wording():
    assert "urgency" in body_codes("This is urgent, reply immediately.")
    assert "urgency" in body_codes("You have 24 hours. Act now!")
    assert "urgency" not in body_codes("See you at the meeting tomorrow afternoon.")


def test_threats():
    assert "threats" in body_codes("Your account will be suspended tonight.")
    assert "threats" in body_codes("We will take legal action against you.")
    assert "threats" not in body_codes("Your account settings were saved, nothing else changed.")


def test_account_verification_requests():
    assert "account_verification" in body_codes("Please verify your account to keep using the service.")
    assert "account_verification" in body_codes("Complete your KYC today.")
    assert "account_verification" in body_codes("We saw suspicious activity on your card.")


def test_prize_offers():
    assert "reward_scam" in body_codes("You have won a lottery. Claim your prize.")
    assert "reward_scam" not in body_codes("Congratulations on your promotion, well done!")


def test_secrecy_and_favours():
    assert "social_engineering" in body_codes("I need a favor. Keep this confidential.")
    assert "social_engineering" not in body_codes("Let's talk about it at lunch.")


def test_generic_greetings():
    assert "generic_greeting" in codes("Dear Customer,\n\nYour order has shipped and will arrive soon.")
    assert "generic_greeting" not in codes("Dear Priya,\n\nYour order has shipped and will arrive soon.")


def test_text_is_matched_in_any_letter_case_and_with_curly_quotes():
    assert "urgency" in body_codes("THIS IS URGENT")
    assert "social_engineering" in body_codes("Please don\u2019t tell anyone about this.")


# ---------- Attachments ----------

def test_risky_attachment_names_and_macros():
    assert "risky_attachment" in body_codes("Please open the attached invoice.exe today.")
    assert "risky_attachment" in body_codes("Open the file and enable macros to see the data.")
    assert "risky_attachment" in body_codes("The photos are in holiday.zip for you.")
    assert "risky_attachment" not in body_codes("The report is attached as report.pdf for you.")


def test_file_names_inside_links_and_addresses_are_not_attachments():
    assert "risky_attachment" not in body_codes("Read https://example.com/guide/index.html for details.")
    assert "risky_attachment" not in body_codes("Write to john.js@example.com for details.")


# ---------- Links (checked with the URL scanner) ----------

def test_dangerous_link_adds_points_and_lists_the_link():
    result = analyze_email("Hello,\n\nOpen http://192.168.10.25/login/verify now.")
    link_signs = [item for item in result["indicators"] if item["code"] == "suspicious_links"]
    assert len(link_signs) == 1
    assert link_signs[0]["points"] == 25
    assert "http://192.168.10.25/login/verify (score 50, Medium)" in link_signs[0]["details"]
    assert result["links_checked"] == 1


def test_link_with_small_warning_signs_adds_fewer_points():
    result = analyze_email("Hello,\n\nSee https://a.b.c.example.com/login for the details.")
    assert {item["code"] for item in result["indicators"]} == {"risky_links"}
    assert result["risk_score"] == 10


def test_clean_links_add_nothing():
    result = analyze_email("Hello,\n\nRead https://docs.python.org/3/ and http://example.org/ please.")
    assert result["indicators"] == []
    assert result["links_checked"] == 2


def test_www_links_are_checked_without_punishing_a_missing_https():
    assert "suspicious_links" in body_codes("Go to www.paypal-secure.xyz/login today")
    assert "risky_links" not in body_codes("Go to www.docs.python.org/3/ today")
    assert body_codes("Go to www.docs.python.org/3/ today") == set()


def test_punctuation_after_a_link_is_ignored():
    result = analyze_email("Hello,\n\nOpen (http://192.168.10.25/login/verify). Thanks!")
    assert result["links_checked"] == 1
    assert "suspicious_links" in {item["code"] for item in result["indicators"]}


def test_only_the_first_ten_links_are_checked():
    links = " ".join(f"https://example.com/page{number}" for number in range(15))
    assert analyze_email("Hello,\n\n" + links)["links_checked"] == 10


# ---------- Sender checks ----------

def test_sender_pretending_to_be_a_known_company():
    text = 'From: "PayPal Support" <help@random-mail.example>\nSubject: Hello there\n\nJust saying hello to you.'
    assert "brand_impersonation" in codes(text)


def test_real_company_sender_is_not_flagged():
    text = 'From: "PayPal" <service@paypal.com>\nSubject: Hello there\n\nJust saying hello to you.'
    assert "brand_impersonation" not in codes(text)


def test_short_brand_names_in_the_sender_name():
    text = 'From: SBI Support <help@random-mail.example>\nSubject: Hello there\n\nJust saying hello to you.'
    assert "brand_impersonation" in codes(text)


def test_reply_to_that_differs_from_the_sender():
    base = "From: Priya <priya@example.org>\nReply-To: {}\nSubject: Hello there\n\nJust saying hello to you."
    assert "reply_to_mismatch" in codes(base.format("someone@other-site.example"))
    assert "reply_to_mismatch" not in codes(base.format("priya.sharma@example.org"))
    assert "reply_to_mismatch" not in codes(base.format("help@mail.example.org"))


def test_missing_sender_is_explained_in_the_summary():
    assert "No From line was included" in analyze_email(MEDIUM_EMAIL)["explanation"]
    assert "No From line was included" not in analyze_email(SAFE_EMAIL)["explanation"]


# ---------- Reading the pasted text ----------

def test_split_email_with_headers():
    headers, body = split_email("From: A <a@example.org>\nSubject: Hi\n\nBody line one\nBody line two")
    assert headers["from"] == "A <a@example.org>"
    assert headers["subject"] == "Hi"
    assert body == "Body line one\nBody line two"


def test_split_email_without_headers_keeps_everything_as_body():
    text = "Urgent: verify now\n\nPlease do it today."
    assert split_email(text) == ({}, text)
    plain = "Dear customer, please read this."
    assert split_email(plain) == ({}, plain)


def test_split_email_joins_long_headers():
    headers, _ = split_email("Subject: A very long\n  subject line\nFrom: a@example.org\n\nBody")
    assert headers["subject"] == "A very long subject line"


def test_the_subject_line_is_checked_too():
    text = "From: Priya <priya@example.org>\nSubject: URGENT action needed\n\nPlease see the notes below."
    assert "urgency" in codes(text)


def test_label_saved_with_the_scan():
    assert build_target("Hello", "a@example.org") == "Email: Hello (from a@example.org)"
    assert build_target("", "") == "Email (no subject)"
    assert build_target("Hello", "") == "Email: Hello"
    assert len(build_target("x" * 500, "")) == len("Email: ") + 120
    assert analyze_email(SAFE_EMAIL)["target"] == "Email: Notes from Friday's meeting (from priya@example.org)"


# ---------- Bad input ----------

def test_unusable_text_is_refused_with_a_clear_message():
    for text in (None, "", "   \n  ", "hi", "x" * 20001):
        with pytest.raises(EmailError) as info:
            analyze_email(text)
        assert str(info.value)


def test_error_messages_explain_what_to_fix():
    with pytest.raises(EmailError) as info:
        analyze_email("hi")
    assert "too short" in str(info.value)
    with pytest.raises(EmailError) as info:
        analyze_email("x" * 20001)
    assert "20,000" in str(info.value)


# ---------- Advice and summary ----------

def test_recommendations():
    assert get_recommendations("Safe", [])
    assert any("Do not click any link" in line for line in get_recommendations("High", []))
    medium = get_recommendations("Medium", ["urgency", "urgency", "unknown_code"])
    assert any("Slow down" in line for line in medium)
    assert len(medium) == len(set(medium))  # no repeated lines


def test_result_has_everything_the_page_needs():
    result = analyze_email(PHISHING_EMAIL)
    assert "100 out of 100" in result["explanation"]
    assert "never opens links or attachments" in result["explanation"]
    assert result["recommendations"]
    assert result["sender"]["domain"] == "paypa1-secure.example"
    for item in result["indicators"]:
        assert item["why"]
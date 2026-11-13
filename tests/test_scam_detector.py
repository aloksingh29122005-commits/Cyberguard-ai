"""Tests for the scam message detector. It only reads text, so these tests need no internet and no database."""
import pytest

from services.scam_detector import (
    MessageError,
    analyze_message,
    build_target,
    find_code_request,
    find_message_links,
    get_recommendations,
    link_main_domain,
)

SAFE_MESSAGE = "Hi Sam, are we still meeting at 6 pm near the library? Let me know if you want to change the time."

MEDIUM_MESSAGE = (
    "Congratulations! You have won a lucky draw prize of Rs 50,000. "
    "To claim your prize, pay a small registration fee today."
)

HIGH_MESSAGE = (
    "SBI ALERT: Your KYC has expired and your account will be blocked today. "
    "Update now: http://sbi-kyc-update.xyz/login and share the OTP you receive. Call 98765 43210."
)


def codes(text):
    """The codes of the warning signs found in a message."""
    return {item["code"] for item in analyze_message(text)["indicators"]}


# ---------- Whole messages ----------

def test_normal_message_has_no_warning_signs():
    result = analyze_message(SAFE_MESSAGE)
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Safe"
    assert result["indicators"] == []


def test_prize_message_scores_medium():
    result = analyze_message(MEDIUM_MESSAGE)
    assert codes(MEDIUM_MESSAGE) == {"reward_scam", "payment_request"}
    assert result["risk_score"] == 45  # 20 + 25
    assert result["risk_level"] == "Medium"


def test_fake_bank_message_is_critical():
    result = analyze_message(HIGH_MESSAGE)
    assert codes(HIGH_MESSAGE) == {"otp_request", "brand_link_mismatch", "suspicious_links", "account_threats"}
    total = sum(item["points"] for item in result["indicators"])
    assert total == 105  # 30 + 30 + 25 + 20
    assert result["risk_score"] == 100  # limited to 100
    assert result["risk_level"] == "Critical"


def test_score_always_equals_the_total_of_the_points():
    for text in (SAFE_MESSAGE, MEDIUM_MESSAGE, HIGH_MESSAGE):
        result = analyze_message(text)
        total = sum(item["points"] for item in result["indicators"])
        assert result["risk_score"] == min(100, total)


def test_warning_signs_are_listed_biggest_first():
    points = [item["points"] for item in analyze_message(HIGH_MESSAGE)["indicators"]]
    assert points == sorted(points, reverse=True)


# ---------- Honest messages must stay quiet ----------

def test_a_real_otp_message_is_not_flagged():
    assert codes("482915 is your OTP for login. Do not share it with anyone. Valid for 10 minutes.") == set()


def test_a_bank_debit_alert_is_only_a_small_clue():
    result = analyze_message("Rs 5000 debited from A/c XX1234 on 12-10-26. If not you, call 1800 123 456. Dear Customer")
    assert {item["code"] for item in result["indicators"]} == {"generic_greeting"}
    assert result["risk_level"] == "Safe"


def test_a_shop_message_with_its_own_link_is_not_flagged():
    assert codes("Your Amazon order has shipped. Track it at https://www.amazon.in/track. Thanks for shopping.") == set()


# ---------- OTP, PIN and codes ----------

def test_requests_for_otp_pin_and_codes_are_found():
    assert "otp_request" in codes("Please share the OTP you received on your phone.")
    assert "otp_request" in codes("Send me your PIN so I can fix it.")
    assert "otp_request" in codes("Please read out the verification code you just got.")
    assert "otp_request" in codes("Kindly send OTP to confirm your booking now.")


def test_advice_about_otp_is_not_a_request():
    assert "otp_request" not in codes("Never share your OTP with anyone. Our staff will not ask for it.")
    assert "otp_request" not in codes("Do not send OTP to anybody, even if they say they are from the bank.")
    assert "otp_request" not in codes("We will never ask you to share the verification code.")


def test_find_code_request():
    assert find_code_request("please share the verification code now") == "share the verification code"
    assert find_code_request("never share the verification code") is None


# ---------- Money and apps ----------

def test_requests_for_money():
    assert "payment_request" in codes("Please send money to this number today.")
    assert "payment_request" in codes("Pay a small fee to release your parcel.")
    assert "payment_request" in codes("Pay the fine to avoid trouble with the office.")
    assert "payment_request" in codes("Scan this QR to receive your refund now.")
    assert "payment_request" in codes("Accept the request on your UPI app.")
    assert "payment_request" not in codes("Thanks for the payment, see you on Monday evening.")


def test_app_installs_and_remote_access():
    assert "app_install" in codes("Please install this app so we can help you with the problem.")
    assert "app_install" in codes("Open AnyDesk and tell me the code so I can fix your phone.")
    assert "app_install" in codes("Download bank_update.apk and open it today.")
    assert "app_install" not in codes("The apple tree in the garden has many apples this year.")


# ---------- Threats, officers, offers ----------

def test_account_threats():
    assert "account_threats" in codes("Your account will be blocked tonight if you do not act.")
    assert "account_threats" in codes("Your KYC is pending. Complete your KYC today.")
    assert "account_threats" in codes("Your SIM card will be deactivated in two hours.")
    assert "account_threats" not in codes("Your settings were saved, nothing else was changed today.")


def test_officers_and_authorities():
    assert "authority_impersonation" in codes("This is the Cyber Crime branch. Your parcel contains illegal items.")
    assert "authority_impersonation" in codes("You are under digital arrest. Do not tell anyone about this call.")
    assert "authority_impersonation" in codes("Income Tax Department notice: contact us now about your refund.")
    assert "authority_impersonation" not in codes("The library opens at nine and closes at five today.")


def test_prize_job_and_delivery_scams():
    assert "reward_scam" in codes("You have won a lottery. Please contact us to receive your gift.")
    assert "job_scam" in codes("Work from home and earn Rs 5000 daily with no interview needed.")
    assert "delivery_scam" in codes("Your parcel could not be delivered. Pay the delivery fee to continue.")
    assert "job_scam" not in codes("My brother works from the office and I work at home.")


def test_urgency_and_trust_tricks():
    assert "urgency" in codes("Reply immediately or you will miss it, this is urgent.")
    assert "social_engineering" in codes("Hi Mum, this is my new number. I lost my phone.")
    assert "social_engineering" in codes("Please keep this secret and do not tell anyone about it.")
    assert "social_engineering" not in codes("Let's talk about it at lunch tomorrow.")


def test_generic_greeting():
    assert "generic_greeting" in codes("Dear Customer, your bill for this month is ready in the app.")
    assert "generic_greeting" not in codes("Dear Priya, your bill for this month is ready in the app.")


def test_some_common_hinglish_phrases():
    found = codes("Aapka account band ho jayega turant. OTP batao aur paise bhejo.")
    assert {"account_threats", "urgency", "otp_request", "payment_request"} <= found


def test_text_is_matched_in_any_letter_case_and_with_curly_quotes():
    assert "urgency" in codes("THIS IS URGENT, PLEASE REPLY")
    assert "social_engineering" in codes("Please don\u2019t tell anyone about this message.")


# ---------- Links ----------

def test_links_without_http_are_found():
    links = find_message_links("Open bit.ly/3xYzAb or sbi-kyc-update.com/login now. Also https://example.org/a.")
    assert "https://bit.ly/3xYzAb" in links
    assert "https://sbi-kyc-update.com/login" in links
    assert "https://example.org/a" in links
    assert len(links) == 3


def test_numbers_and_email_addresses_are_not_links():
    assert find_message_links("Rs.500 paid at 5.30 pm. Write to help@example.com for details.") == []


def test_shortened_link_adds_points_and_lists_the_link():
    result = analyze_message("Open bit.ly/3xYzAb to see the photos from the party.")
    assert {item["code"] for item in result["indicators"]} == {"shortened_link"}
    assert result["risk_score"] == 15
    assert result["indicators"][0]["details"] == ["https://bit.ly/3xYzAb"]


def test_dangerous_link_adds_points_and_lists_the_link():
    result = analyze_message("Open http://192.168.10.25/login/verify now to see it.")
    link_signs = [item for item in result["indicators"] if item["code"] == "suspicious_links"]
    assert len(link_signs) == 1
    assert link_signs[0]["points"] == 25
    assert "http://192.168.10.25/login/verify (score 50, Medium)" in link_signs[0]["details"]


def test_link_with_small_warning_signs_adds_fewer_points():
    result = analyze_message("See https://a.b.c.example.com/login for the details please.")
    assert {item["code"] for item in result["indicators"]} == {"risky_links"}
    assert result["risk_score"] == 10


def test_clean_links_add_nothing():
    result = analyze_message("Read https://docs.python.org/3/ and example.org/news please.")
    assert result["indicators"] == []
    assert result["links_checked"] == 2


def test_a_known_company_name_with_a_link_to_another_website():
    result = analyze_message("SBI: your KYC is pending, update at bit.ly/3xYzAb")
    mismatch = [item for item in result["indicators"] if item["code"] == "brand_link_mismatch"]
    assert len(mismatch) == 1
    assert "'sbi'" in mismatch[0]["text"]
    assert "bit.ly" in mismatch[0]["text"]
    assert "brand_link_mismatch" in codes("HDFC Bank: view your statement at https://my-statement.example/login")
    assert "brand_link_mismatch" in codes("Your State Bank account: see https://kyc-help.example/ today")


def test_a_known_company_name_with_its_own_link_is_fine():
    assert "brand_link_mismatch" not in codes("Amazon: track your order at https://www.amazon.in/track today")
    assert "brand_link_mismatch" not in codes("SBI: see your account at https://sbi.co.in/web/personal today")
    assert "brand_link_mismatch" not in codes("Amazon: your order has shipped, thanks for shopping with us")


def test_main_domain_of_a_link():
    assert link_main_domain("https://www.sbi.co.in/web") == "sbi.co.in"
    assert link_main_domain("https://bit.ly/abc") == "bit.ly"
    assert link_main_domain("http://192.168.10.25/login") == "192.168.10.25"


# ---------- The label saved with the scan ----------

def test_label_hides_long_numbers_and_is_short():
    label = build_target("Your OTP is 482915 and your card is 1234 5678 9012 3456, keep them safe please")
    assert "482915" not in label
    assert "1234" not in label
    assert "****" in label
    assert label.startswith("Message: ")
    assert len(label) <= len("Message: ") + 50 + 3


def test_label_does_not_contain_the_end_of_a_long_message():
    result = analyze_message("Hello there! Please keep code 482915 safe. my-private-sentence-4711")
    assert "my-private-sentence-4711" not in result["target"]
    assert "482915" not in result["target"]


def test_short_message_label_is_kept_whole():
    assert build_target("Hello  there,\nhow are you?") == "Message: Hello there, how are you?"


# ---------- Bad input ----------

def test_unusable_text_is_refused_with_a_clear_message():
    for text in (None, "", "   \n  ", "hi", "x" * 3001):
        with pytest.raises(MessageError) as info:
            analyze_message(text)
        assert str(info.value)


def test_error_messages_explain_what_to_fix():
    with pytest.raises(MessageError) as info:
        analyze_message("hi")
    assert "too short" in str(info.value)
    with pytest.raises(MessageError) as info:
        analyze_message("x" * 3001)
    assert "3,000" in str(info.value)


# ---------- Advice and summary ----------

def test_recommendations():
    assert get_recommendations("Safe", [])
    assert any("Do not click any link, call any number" in line for line in get_recommendations("High", []))
    medium = get_recommendations("Medium", ["urgency", "urgency", "unknown_code"])
    assert any("Slow down" in line for line in medium)
    assert len(medium) == len(set(medium))  # no repeated lines


def test_result_has_everything_the_page_needs():
    result = analyze_message(HIGH_MESSAGE)
    assert "100 out of 100" in result["explanation"]
    assert "never opens links, calls numbers or replies" in result["explanation"]
    assert result["recommendations"]
    for item in result["indicators"]:
        assert item["why"]
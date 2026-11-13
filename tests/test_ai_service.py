"""Tests for the AI service. No internet is used: the HTTP call is replaced by a fake answer."""
import json
from unittest.mock import patch

import pytest
import requests

from services.ai_service import (
    DEFAULT_FALLBACK,
    MAX_MESSAGE_CHARS,
    MAX_MESSAGES,
    MAX_REPLY_CHARS,
    SAFETY_RULES,
    TEST_QUESTION,
    AIService,
    AISettings,
    RateLimiter,
    redact_sensitive,
)

SECRET_KEY = "sk-test-SECRETKEY1234567890abcdefghij"

ANTHROPIC = AISettings(provider="anthropic", api_key=SECRET_KEY, model="claude-test-model")
COMPATIBLE = AISettings(provider="openai_compatible", api_key=SECRET_KEY, model="chat-test-model",
                        base_url="https://api.example.com/v1")
LOCAL = AISettings(provider="openai_compatible", model="llama-test", base_url="http://localhost:11434/v1")

QUESTION = [{"role": "user", "content": "What is phishing?"}]


class FakeResponse:
    """A stand-in for the answer of requests.post."""

    def __init__(self, status=200, data=None, text=None):
        self.status_code = status
        self._data = data
        self.text = text if text is not None else json.dumps(data if data is not None else {})

    def json(self):
        if self._data is None:
            raise ValueError("not json")
        return self._data


def anthropic_answer(text="Phishing is a trick to steal your details."):
    return FakeResponse(200, {"content": [{"type": "text", "text": text}]})


def compatible_answer(text="Phishing is a trick to steal your details."):
    return FakeResponse(200, {"choices": [{"message": {"role": "assistant", "content": text}}]})


def ask(settings, answer, messages=QUESTION, user_id=1, limiter=None, **kwargs):
    """Call AIService.ask with a fake HTTP answer. Returns (result, the mock)."""
    with patch("services.ai_service.requests.post", return_value=answer) as mock_post:
        result = AIService(settings, limiter=limiter or RateLimiter()).ask(user_id, "Be helpful.", messages, **kwargs)
    return result, mock_post


# ---------- Settings ----------

def test_the_ai_is_off_by_default():
    settings = AISettings()
    assert settings.provider == "none"
    assert not settings.is_configured
    assert "switched off" in settings.problem


def test_unknown_provider_and_missing_pieces_are_explained():
    assert "AI_PROVIDER must be" in AISettings(provider="magic").problem
    assert "AI_MODEL" in AISettings(provider="anthropic", api_key="k").problem
    assert "AI_API_KEY" in AISettings(provider="anthropic", model="m").problem
    assert "AI_BASE_URL is not set" in AISettings(provider="openai_compatible", api_key="k", model="m").problem
    assert ANTHROPIC.is_configured and ANTHROPIC.problem == ""
    assert COMPATIBLE.is_configured


def test_a_service_on_this_computer_needs_no_key_but_other_http_addresses_are_refused():
    assert LOCAL.is_configured
    assert "AI_API_KEY" in AISettings(provider="openai_compatible", model="m", base_url="https://api.example.com/v1").problem
    insecure = AISettings(provider="openai_compatible", api_key="k", model="m", base_url="http://api.example.com/v1")
    assert "https://" in insecure.problem
    assert "valid web address" in AISettings(provider="openai_compatible", api_key="k", model="m", base_url="ftp://x.example").problem
    assert "valid web address" in AISettings(provider="openai_compatible", api_key="k", model="m", base_url="not a url").problem


def test_the_key_never_appears_in_text_form_of_the_settings_or_the_description():
    assert SECRET_KEY not in repr(ANTHROPIC)
    assert SECRET_KEY not in str(ANTHROPIC)
    description = AIService(ANTHROPIC).describe()
    assert SECRET_KEY not in json.dumps(description)
    assert description["key_set"] is True
    assert description["host"] == "api.anthropic.com"
    assert description["provider_label"] == "Anthropic (Claude)"
    assert AIService(AISettings()).describe()["key_set"] is False


def test_settings_are_read_from_the_config_and_wrong_numbers_use_the_defaults():
    config = {"AI_PROVIDER": " Anthropic ", "AI_API_KEY": f" {SECRET_KEY} ", "AI_MODEL": " m ",
              "AI_TIMEOUT_SECONDS": "abc", "AI_MAX_OUTPUT_TOKENS": "-5", "AI_MAX_CALLS_PER_HOUR": "10"}
    settings = AISettings.from_config(config)
    assert settings.provider == "anthropic"
    assert settings.api_key == SECRET_KEY
    assert settings.model == "m"
    assert settings.timeout == 30
    assert settings.max_tokens == 600
    assert settings.max_calls_per_hour == 10
    assert AISettings.from_config({}).provider == "none"


# ---------- Cleaning text before it is sent ----------

def test_codes_numbers_and_emails_are_hidden():
    cleaned = redact_sensitive("My OTP is 482915, my phone is 98765 43210 and my mail is sam@example.com")
    assert "482915" not in cleaned and "98765" not in cleaned and "sam@example.com" not in cleaned
    assert cleaned == "My OTP is [hidden], my phone is [number] and my mail is [email]"


def test_card_numbers_and_passwords_are_hidden():
    cleaned = redact_sensitive("Card 1234 5678 9012 3456, password is Hunter2! and PIN: 4821, cvv 123")
    for secret in ("1234 5678", "Hunter2", "4821", "123"):
        assert secret not in cleaned
    assert "password is [hidden]" in cleaned


def test_long_secret_looking_tokens_are_hidden_without_leaving_pieces():
    cleaned = redact_sensitive("key abcdef1234567890abcdef1234567890 and sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv1234567890")
    assert cleaned == "key [secret] and [secret]"


def test_links_keep_the_website_but_lose_login_query_and_fragment():
    cleaned = redact_sensitive("Check http://user:pw@evil-site.example/login/verify?token=abc123#part now")
    assert cleaned == "Check http://evil-site.example/login/verify?[removed] now"
    assert "pw" not in cleaned and "token" not in cleaned


def test_normal_words_years_dates_and_long_link_words_stay():
    text = "In 2026-10-27 the sbi-kyc-update-account-verification page appeared at https://sbi-kyc-update-account-verification.example/a/b"
    assert redact_sensitive(text) == text


def test_cleaning_is_safe_to_repeat_and_shortens_long_text():
    once = redact_sensitive("OTP is 482915 and mail sam@example.com")
    assert redact_sensitive(once) == once
    long_text = redact_sensitive("word " * 2000)
    assert len(long_text) <= MAX_MESSAGE_CHARS and long_text.endswith("...")
    assert redact_sensitive(None) == ""
    assert redact_sensitive("a\x00b\x07c") == "abc"


# ---------- Limits per user ----------

def test_a_user_can_ask_only_so_often_per_hour():
    now = [0.0]
    limiter = RateLimiter(clock=lambda: now[0])
    assert [limiter.allow(1, 3) for _ in range(4)] == [True, True, True, False]
    assert limiter.allow(2, 3) is True  # another user has their own count
    now[0] = 3599
    assert limiter.allow(1, 3) is False
    now[0] = 3601  # the first calls are older than an hour
    assert limiter.allow(1, 3) is True


# ---------- Calling Anthropic ----------

def test_anthropic_request_has_the_right_shape():
    result, mock_post = ask(ANTHROPIC, anthropic_answer())
    assert result.source == "ai"
    assert result.text == "Phishing is a trick to steal your details."

    args, kwargs = mock_post.call_args
    assert args[0] == "https://api.anthropic.com/v1/messages"
    assert kwargs["headers"]["x-api-key"] == SECRET_KEY
    assert kwargs["headers"]["anthropic-version"] == "2023-06-01"
    assert kwargs["timeout"] == 30
    payload = kwargs["json"]
    assert payload["model"] == "claude-test-model"
    assert payload["max_tokens"] == 600
    assert payload["messages"] == QUESTION
    assert payload["system"].startswith("Be helpful.")
    assert SAFETY_RULES in payload["system"]


def test_anthropic_answer_with_several_text_blocks_is_joined():
    answer = FakeResponse(200, {"content": [{"type": "text", "text": "One. "}, {"type": "other"}, {"type": "text", "text": "Two."}]})
    result, _ = ask(ANTHROPIC, answer)
    assert result.text == "One. Two."


# ---------- Calling an OpenAI-compatible service ----------

def test_openai_compatible_request_has_the_right_shape():
    result, mock_post = ask(COMPATIBLE, compatible_answer())
    assert result.source == "ai"

    args, kwargs = mock_post.call_args
    assert args[0] == "https://api.example.com/v1/chat/completions"
    assert kwargs["headers"]["Authorization"] == "Bearer " + SECRET_KEY
    payload = kwargs["json"]
    assert payload["model"] == "chat-test-model"
    assert payload["max_tokens"] == 600
    assert payload["messages"][0]["role"] == "system"
    assert SAFETY_RULES in payload["messages"][0]["content"]
    assert payload["messages"][1:] == QUESTION


def test_a_service_on_this_computer_gets_no_authorization_header():
    result, mock_post = ask(LOCAL, compatible_answer())
    assert result.source == "ai"
    assert "Authorization" not in mock_post.call_args.kwargs["headers"]
    assert mock_post.call_args.args[0] == "http://localhost:11434/v1/chat/completions"


def test_newer_models_that_want_max_completion_tokens_get_one_retry():
    refused = FakeResponse(400, {"error": {"message": "Use max_completion_tokens instead of max_tokens"}})
    with patch("services.ai_service.requests.post", side_effect=[refused, compatible_answer("Second try worked.")]) as mock_post:
        result = AIService(COMPATIBLE, limiter=RateLimiter()).ask(1, "Help.", QUESTION)
    assert result.source == "ai" and result.text == "Second try worked."
    assert mock_post.call_count == 2
    first, second = mock_post.call_args_list[0].kwargs["json"], mock_post.call_args_list[1].kwargs["json"]
    assert "max_tokens" in first and "max_completion_tokens" not in first
    assert "max_tokens" not in second and second["max_completion_tokens"] == 600


# ---------- When the AI cannot answer ----------

def test_not_configured_means_fallback_and_no_call():
    result, mock_post = ask(AISettings(), anthropic_answer())
    assert result.source == "fallback"
    assert result.text == DEFAULT_FALLBACK
    assert "switched off" in result.reason
    mock_post.assert_not_called()


def test_the_caller_can_give_its_own_fallback_text():
    result, _ = ask(AISettings(), anthropic_answer(), fallback_text="Rule-based explanation.")
    assert result.text == "Rule-based explanation."


def test_error_answers_become_the_fallback_with_a_clear_reason():
    cases = {
        401: "did not accept the key",
        403: "did not accept the key",
        429: "too many requests",
        500: "error (status 500)",
        404: "error (status 404)",
    }
    for status, expected in cases.items():
        result, _ = ask(ANTHROPIC, FakeResponse(status, {"error": {"message": "nope"}}))
        assert result.source == "fallback"
        assert expected in result.reason
        assert result.text == DEFAULT_FALLBACK


def test_network_problems_become_the_fallback():
    for error, expected in ((requests.exceptions.Timeout(), "in time"), (requests.exceptions.ConnectionError(), "could not be reached")):
        with patch("services.ai_service.requests.post", side_effect=error):
            result = AIService(ANTHROPIC, limiter=RateLimiter()).ask(1, "Help.", QUESTION)
        assert result.source == "fallback"
        assert expected in result.reason


def test_unreadable_or_empty_answers_become_the_fallback():
    for answer, expected in (
        (FakeResponse(200, None, text="<html>oops</html>"), "could not read"),
        (FakeResponse(200, ["not", "a", "dict"]), "could not read"),
        (anthropic_answer("   "), "empty answer"),
        (FakeResponse(200, {"content": []}), "empty answer"),
    ):
        result, _ = ask(ANTHROPIC, answer)
        assert result.source == "fallback", expected
        assert expected in result.reason
    result, _ = ask(COMPATIBLE, FakeResponse(200, {"choices": [{"message": {"content": None}}]}))
    assert result.source == "fallback" and "empty answer" in result.reason


def test_an_unexpected_crash_inside_the_call_never_reaches_the_user():
    with patch("services.ai_service.requests.post", side_effect=RuntimeError("boom with " + SECRET_KEY)):
        result = AIService(ANTHROPIC, limiter=RateLimiter()).ask(1, "Help.", QUESTION)
    assert result.source == "fallback"
    assert "unexpected" in result.reason
    assert SECRET_KEY not in result.reason + result.detail + result.text


def test_the_key_is_removed_from_the_providers_error_message():
    answer = FakeResponse(401, {"error": {"message": f"Incorrect API key provided: {SECRET_KEY}. Model gone."}})
    result, _ = ask(ANTHROPIC, answer)
    assert result.source == "fallback"
    assert SECRET_KEY not in result.detail and "SECRETKEY" not in result.detail
    assert "Model gone" in result.detail


def test_the_providers_error_message_is_shortened():
    answer = FakeResponse(500, {"error": {"message": "x " * 500}})
    result, _ = ask(ANTHROPIC, answer)
    assert len(result.detail) <= 200


def test_a_very_long_answer_is_shortened():
    result, _ = ask(ANTHROPIC, anthropic_answer("word " * 5000))
    assert len(result.text) <= MAX_REPLY_CHARS and result.text.endswith("...")


# ---------- What is sent ----------

def test_secrets_are_removed_inside_ask_even_if_the_caller_forgot():
    messages = [{"role": "user", "content": "My OTP is 482915 and my card is 1234 5678 9012 3456, mail sam@example.com"}]
    _, mock_post = ask(ANTHROPIC, anthropic_answer(), messages=messages)
    sent = json.dumps(mock_post.call_args.kwargs["json"])
    for secret in ("482915", "1234 5678", "sam@example.com"):
        assert secret not in sent
    assert "[hidden]" in sent and "[email]" in sent


def test_only_the_newest_messages_are_sent_and_they_start_with_the_user():
    messages = []
    for number in range(20):
        messages.append({"role": "user", "content": f"question {number}"})
        messages.append({"role": "assistant", "content": f"answer {number}"})
    _, mock_post = ask(ANTHROPIC, anthropic_answer(), messages=messages)
    sent = mock_post.call_args.kwargs["json"]["messages"]
    assert len(sent) <= MAX_MESSAGES
    assert sent[0]["role"] == "user"
    assert sent[-1]["content"] == "answer 19"


def test_a_wrong_role_is_a_programming_error_and_empty_messages_give_the_fallback():
    with pytest.raises(ValueError):
        AIService(ANTHROPIC, limiter=RateLimiter()).ask(1, "Help.", [{"role": "system", "content": "x"}])
    result, mock_post = ask(ANTHROPIC, anthropic_answer(), messages=[{"role": "user", "content": "   "}])
    assert result.source == "fallback" and "nothing to ask" in result.reason
    mock_post.assert_not_called()


def test_the_limit_per_hour_gives_the_fallback_without_calling_the_ai():
    limited = AISettings(provider="anthropic", api_key=SECRET_KEY, model="m", max_calls_per_hour=2)
    limiter = RateLimiter()
    with patch("services.ai_service.requests.post", return_value=anthropic_answer()) as mock_post:
        service = AIService(limited, limiter=limiter)
        sources = [service.ask(7, "Help.", QUESTION).source for _ in range(3)]
        other_user = service.ask(8, "Help.", QUESTION).source
    assert sources == ["ai", "ai", "fallback"]
    assert other_user == "ai"
    assert mock_post.call_count == 3
    assert "limit" in service.ask(7, "Help.", QUESTION).reason


def test_the_connection_test_uses_a_fixed_harmless_question():
    with patch("services.ai_service.requests.post", return_value=anthropic_answer("A trick.")) as mock_post:
        result = AIService(ANTHROPIC, limiter=RateLimiter()).test_connection(1)
    assert result.source == "ai" and result.text == "A trick."
    assert mock_post.call_args.kwargs["json"]["messages"] == [{"role": "user", "content": TEST_QUESTION}]
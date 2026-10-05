"""B16 — India-specific citizen features: scam-message patterns and reporting helpers.

* The pattern catalogue is a *transparent rule list* (fixed weights, plain-English why/what-to-do), not a model: each pattern is
  checked on messages that should match and on genuine messages that must not (a real OTP SMS says "do not share it").
* URLs in a message go through the B4 look-alike detector; a brand named next to a foreign link is caught without any scam phrase.
* The report kit contains only what ThreatFusion observed — no personal data — puts the helpline first when money was lost, and
  never claims to submit anything.
"""

from __future__ import annotations

import httpx
import pytest
import pytest_asyncio

from app.india.report_kit import build_report_kit
from app.india.scam_patterns import PATTERNS, analyze_text

AUTH = {"Authorization": "Bearer test-token-0123456789abcdef0123456789abcdef"}


def ids(text: str) -> set[str]:
    return {m.id for m in analyze_text(text).matches}


@pytest.mark.parametrize("text,expected", [
    ("To receive Rs 5000 cashback please enter your UPI PIN in the app now", "upi_pin_to_receive"),
    ("A collect request has been sent. Approve the payment request to receive your refund", "upi_collect_request"),
    ("Dear customer your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.in", "kyc_expiry"),
    ("Your KYC is pending. Complete KYC or your account stands suspended", "kyc_expiry"),
    ("Your PAN is not linked and will become inoperative", "kyc_expiry"),
    ("Dear consumer your electricity connection will be disconnected tonight at 9:30 pm. Call 98XXXXXXXX", "electricity_disconnection"),
    ("Your parcel is held at customs. Pay Rs 49 redelivery fee: bit.ly/3xyz", "parcel_customs"),
    ("India Post: your address is incomplete, update within 24 hours", "parcel_customs"),
    ("Congratulations! You have won Rs 25 lakh in the KBC lucky draw. Claim your prize", "lottery_prize"),
    ("Part time work from home, earn Rs 3000 per day. Join telegram for tasks", "job_task_scam"),
    ("Like YouTube videos and earn Rs 50 per video, daily payment", "job_task_scam"),
    ("Instant loan without documents or CIBIL, pre-approved loan click link to apply", "loan_app"),
    ("This is CBI. A parcel in your name contains drugs. You are under digital arrest, do not disconnect the video call", "digital_arrest"),
    ("Your SIM will be blocked within 2 hours by TRAI. Press 9 to talk to officer", "sim_block_trai"),
    ("Income tax refund of Rs 15,200 is pending. Click the link to claim your refund", "income_tax_refund"),
    ("Please share the OTP you received to confirm", "credential_request"),
    ("Tell me your CVV and card number to verify", "credential_request"),
    ("Download AnyDesk and give me the 9 digit code so I can fix your account", "remote_access_app"),
    ("Install the bank app from this link: http://files.example.top/sbi-yono.apk", "apk_link"),
    ("Urgent! Last warning, act now", "urgency"),
    ("Dear customer, your bank statement is ready", "generic_greeting"),
])
def test_known_scam_patterns_are_recognised(text, expected) -> None:
    assert expected in ids(text), (text, ids(text))


@pytest.mark.parametrize("text", [
    "123456 is your OTP for login. Do not share it with anyone. -HDFC Bank",
    "Never share your OTP, PIN or CVV with anyone, including bank staff.",
    "Please do not install AnyDesk or any remote app if someone asks you to.",
    "Hey, are we meeting at 6 for dinner? I will order from Zomato.",
    "Your Swiggy order #4521 has been delivered. Rate your experience.",
    "Reminder: your electricity bill of Rs 1,240 is due on 15th. Pay via the official app.",
    "Mom, I updated my college form today. See you on Sunday.",
    "Your appointment with Dr. Rao is confirmed for tomorrow at 10:30 am.",
    "Happy birthday! Wishing you a wonderful year ahead.",
])
def test_genuine_messages_are_not_flagged(text) -> None:
    a = analyze_text(text)
    assert a.risk in ("none", "low") and a.score < 0.4, (text, [m.id for m in a.matches], a.score)
    assert not {"credential_request", "remote_access_app", "kyc_expiry", "digital_arrest", "upi_pin_to_receive"} & {m.id for m in a.matches}, text


def test_the_score_is_the_strongest_flag_plus_a_small_bonus_per_extra_category() -> None:
    one = analyze_text("Please share the OTP you received to confirm")
    assert one.score == 0.9 and one.risk == "high" and "0.90" in one.arithmetic
    many = analyze_text("Your KYC is pending and your account will be blocked today. Urgent! Share your OTP now. Dear customer")
    cats = {m.category for m in many.matches}
    assert len(cats) >= 3 and many.score == pytest.approx(min(1.0, 0.9 + 0.05 * (len(cats) - 1)), abs=0.01) and many.risk == "high"
    assert "other categories" in many.arithmetic
    none = analyze_text("See you tomorrow.")
    assert none.score == 0.0 and none.risk == "none" and "no known pattern" in none.arithmetic


def test_every_result_says_it_is_not_a_verdict_and_gives_advice() -> None:
    a = analyze_text("Share the OTP you received to confirm your KYC today")
    assert any("not a verdict" in s for s in a.limits) and any("No match does not mean safe" in s for s in a.limits)
    assert a.advice and any("1930" in s for s in a.advice)
    for m in a.matches:
        assert m.why and m.advice and m.evidence


def test_an_evidence_snippet_comes_from_the_message() -> None:
    text = "Hello. Your SIM will be blocked within 2 hours by TRAI. Call now."
    m = next(m for m in analyze_text(text).matches if m.id == "sim_block_trai")
    assert m.evidence in " ".join(text.split()) or m.evidence.split()[0] in text


def test_a_lookalike_link_is_caught_by_the_brand_detector_without_any_scam_phrase() -> None:
    a = analyze_text("Your statement is ready: https://hdfcbank-netbanking-login.com/verify")
    assert "lookalike_link" in {m.id for m in a.matches} and a.risk in ("medium", "high")
    u = a.urls[0]
    assert u.host == "hdfcbank-netbanking-login.com" and u.brand_check.match.brand == "HDFC Bank" and "hdfcbank.com" in u.note


def test_a_brand_named_next_to_a_foreign_link_is_flagged_but_the_brands_own_link_is_not() -> None:
    bad = analyze_text("HDFC Bank: please review your details at http://secure-review.example-site.top/login")
    assert "brand_with_foreign_link" in {m.id for m in bad.matches}
    good = analyze_text("HDFC Bank: view your statement at https://www.hdfcbank.com/personal")
    assert "brand_with_foreign_link" not in {m.id for m in good.matches} and good.risk in ("none", "low")


def test_link_shorteners_are_noted() -> None:
    a = analyze_text("Pay your pending fee at bit.ly/3abc12")
    assert any(u.shortener for u in a.urls) and "link_shortener" in {m.id for m in a.matches}


def test_junk_and_huge_inputs_are_handled() -> None:
    assert analyze_text("").risk == "none"
    assert analyze_text("\x00\x01 ☃ " * 10).risk == "none"
    big = analyze_text("hello " * 5000 + " share your OTP")
    assert big.truncated is True and big.risk == "none", "text past the cap is not read (and the result says so)"
    assert analyze_text("x" * 20000 + "<script>").risk == "none"


def test_the_catalogue_is_well_formed() -> None:
    assert len({p.id for p in PATTERNS}) == len(PATTERNS) >= 14
    assert all(0 < p.weight <= 1 and p.why and p.advice and p.label for p in PATTERNS)
    assert all(p.regex.search("") is None for p in PATTERNS), "no pattern matches the empty string"


# ── report kit ──────────────────────────────────────────────────────────────
def test_the_kit_has_no_personal_data_and_never_claims_to_submit() -> None:
    kit = build_report_kit("website", host="paypa1-secure.com", url="https://paypa1-secure.com/login", reasons=["The domain imitates PayPal."],
                           brand="PayPal", brand_domain="paypal.com", scan_id="abc-123")
    assert "paypa1-secure.com" in kit.summary_text and "PayPal" in kit.summary_text and "abc-123" in kit.summary_text
    assert "IST" in kit.summary_text
    assert any("does not submit anything" in r for r in kit.reminders)
    names = [c.name for c in kit.channels]
    assert "National Cyber Crime Reporting Portal" in names and "CERT-In incident reporting" in names and any("PayPal" in n for n in names)
    assert kit.kind == "website"


def test_when_money_was_lost_the_helpline_comes_first_with_time_critical_steps() -> None:
    kit = build_report_kit("message", message_excerpt="Share OTP now", lost_money=True)
    assert kit.channels[0].id == "helpline_1930" and kit.channels[0].how == "Call 1930"
    assert kit.channels[1].id == "your_bank"
    assert "1930" in kit.steps[0] and any("Chakshu" in s for s in kit.steps)
    calm = build_report_kit("message", message_excerpt="Share OTP now")
    assert calm.channels[0].id == "chakshu" and "helpline_1930" not in [c.id for c in calm.channels]


def test_a_message_excerpt_is_trimmed_in_the_summary() -> None:
    kit = build_report_kit("message", message_excerpt="word " * 400)
    assert len(kit.summary_text) < 1200


# ── endpoints ───────────────────────────────────────────────────────────────
@pytest_asyncio.fixture
async def client(monkeypatch):
    from app.core.config import get_settings
    from app.main import app

    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "1000")
    get_settings.cache_clear()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost", headers=AUTH) as c:
        yield c
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_analyze_text_endpoint(client) -> None:
    r = await client.post("/india/analyze-text", json={"text": "Your KYC is pending, click http://sbi-kyc-update.in to avoid blocking"})
    body = r.json()
    assert r.status_code == 200 and body["analysis"]["risk"] in ("medium", "high") and body["analysis"]["matches"]
    hi = await client.post("/india/analyze-text", json={"text": "hello", "language": "hi"})
    assert hi.status_code == 200 and "English" in hi.json()["notes"][0]
    assert (await client.post("/india/analyze-text", json={"text": ""})).status_code == 422
    assert (await client.post("/india/analyze-text", json={"text": "x"}, headers={"Authorization": ""})).status_code in (401, 403)


@pytest.mark.asyncio
async def test_the_report_kit_endpoints(client) -> None:
    r = await client.post("/india/report-kit", json={"kind": "website", "host": "evil.example.com", "reasons": ["a", "b"], "lost_money": True})
    assert r.status_code == 200 and r.json()["channels"][0]["id"] == "helpline_1930"
    assert (await client.get("/india/scan/does-not-exist/report-kit")).status_code == 404


@pytest.mark.asyncio
async def test_the_report_kit_from_a_stored_scan(client, monkeypatch) -> None:
    import app.core.validation as validation
    from app.core.hub import hub

    async def _ok(target):
        return True, {"success": True}, target

    monkeypatch.setattr(validation, "validate_domain_target", _ok)
    monkeypatch.setenv("USE_MOCK_DATA", "true")
    from app.core.config import get_settings
    get_settings.cache_clear()
    hub.reset()
    scan = (await client.post("/scan", json={"target": "evil-login.example.com", "target_type": "domain"})).json()["result"]
    kit = (await client.get(f"/india/scan/{scan['scan_id']}/report-kit")).json()
    assert scan["scan_id"] in kit["summary_text"] and "evil-login.example.com" in kit["summary_text"]
    assert any("Listed by" in line for line in kit["summary_text"].splitlines()), "the listing reasons from the scan are carried over"
    get_settings.cache_clear()
    hub.reset()

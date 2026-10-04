"""
Scam-message patterns for India (B16)
=====================================

Most Indian phishing reaches a person as a **message** (SMS, WhatsApp, a call script) long before it is a web page: the "your KYC
expires today" text, the UPI collect request, the "parcel held at customs" link, the "digital arrest" video call.  This module reads a
pasted message (or a page's visible text) and says, in plain English, *which known scam pattern it resembles and why*.

What it is — and is not
-----------------------
* A **transparent rule catalogue**: every pattern has an id, a category, a regular expression, a fixed weight and a plain-English
  "why this is a red flag" and "what to do".  The weights were written down *before* any data was looked at and are **not**
  fitted to anything; the score is the strongest matched category plus a small bonus per additional category (capped), so the
  arithmetic can be read off the result.  Nothing is learned and no probability is claimed.
* **Not a verdict.**  A message with no match is *not* thereby safe (scammers rewrite their scripts); a message with a match may be
  genuine (a real bank also writes "KYC").  The result always says so.
* English only today (see ``docs/ROADMAP.md``: Hindi / Tamil copy needs a decision and a native reviewer — a wrong safety
  sentence in someone's own language is worse than an English one).  The patterns also match common Hinglish spellings.
* URLs found in the text are checked with the B4 look-alike detector, so "HDFC Bank" next to a non-HDFC link is caught even when no
  scam phrase appears.

The catalogue reflects publicly described Indian fraud patterns (RBI, NPCI, I4C / cybercrime.gov.in advisories).  It is deliberately
modest: each pattern is something an ordinary person can verify for themselves.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel, Field

from app.core.targets import canonicalize
from functools import lru_cache

from app.ml.brands import CURATED_BRANDS, BrandIndex
from app.ml.lookalike import assess_lookalike
from app.models.schemas import BrandCheck, TargetType

I = re.IGNORECASE


@dataclass(frozen=True)
class Pattern:
    id: str
    category: str
    label: str
    weight: float                      # strength of this red flag on its own, 0-1 (fixed a priori)
    regex: re.Pattern
    why: str
    advice: str
    guard_negation: bool = False       # ignore matches like 'do NOT share your OTP' (a legitimate warning)


def _p(id: str, category: str, label: str, weight: float, regex: str, why: str, advice: str, guard_negation: bool = False) -> Pattern:
    return Pattern(id, category, label, weight, re.compile(regex, I | re.S), why, advice, guard_negation)


PATTERNS: tuple[Pattern, ...] = (
    _p("upi_pin_to_receive", "upi", "Asks for a UPI PIN to receive money", 0.95,
       r"(enter|share|put|type|tell|send)\W+(\w+\W+){0,4}(upi\s*)?(pin|m-?pin)\b.{0,80}\b(receive|get|credit|claim|refund|cashback|reward)|"
       r"\b(receive|get|credit|claim)\b.{0,80}\b(enter|share|put|type|tell|send)\W+(\w+\W+){0,4}(upi\s*)?(pin|m-?pin)\b",
       "You never need a PIN to *receive* money. A PIN is only for sending it.",
       "Do not enter your PIN. If you already did, call your bank and 1930 immediately.", guard_negation=True),
    _p("upi_collect_request", "upi", "A UPI collect request you did not ask for", 0.8,
       r"(collect|payment)\s*request.{0,60}(approve|accept|confirm)|(approve|accept)\W+(\w+\W+){0,4}(collect|payment)\s*request",
       "Approving a 'collect request' sends money *out* of your account.",
       "Decline requests you did not start yourself; check the app, never the message."),
    _p("kyc_expiry", "kyc", "Your KYC / account will be blocked", 0.8,
       r"(kyc|pan|aadhaar|aadhar|account|card|wallet)\W+(\w+\W+){0,6}(will\s+be|is\s+(going\s+to\s+be|being)|has\s+been|stands?)\W+(\w+\W+){0,2}(block|suspend|deactivat|clos|freez|expir)|"
       r"(update|complete|verify|renew)\W+(\w+\W+){0,3}kyc|kyc\W+(\w+\W+){0,3}(pending|expired|incomplete|not\s+updated)|"
       r"pan\W+(\w+\W+){0,4}(not\s+linked|inoperative|blocked)",
       "Banks do not block accounts over an SMS link, and KYC updates are done in the bank's own app or branch.",
       "Open your bank's app yourself, or call the number printed on your card or passbook. Do not tap the link."),
    _p("electricity_disconnection", "utility", "Electricity / utility will be disconnected tonight", 0.75,
       r"(electricity|power|bijli|bill)\W+(\w+\W+){0,8}(disconnect\w*|cut|terminat\w*|suspend\w*)\W+(\w+\W+){0,6}(tonight|today|\d{1,2}[:.]\d{2}|\d+\s*(pm|am)|hours)",
       "Utilities do not disconnect supply by SMS the same evening and ask you to call a mobile number.",
       "Check your bill in the utility's official app or website. Do not call the number in the message."),
    _p("parcel_customs", "parcel", "A parcel is held / address incomplete / pay a small fee", 0.7,
       r"(parcel|courier|package|consignment|delivery)\W+(\w+\W+){0,8}(held|stuck|on\s+hold|returned|customs|address\s+(is\s+)?(incomplete|invalid|wrong)|redeliver|re-?schedule)|"
       r"(india\s*post|dtdc|bluedart|delhivery|fedex|dhl)\W+(\w+\W+){0,10}(fee|pay|charge|address)",
       "Real couriers rarely ask for a 'small fee' through a link in a text message.",
       "Track the parcel on the courier's own website using the number from your order, not the link."),
    _p("lottery_prize", "prize", "You won a lottery / prize / reward", 0.8,
       r"(you\s+(have\s+)?won|congratulations|lucky\s+(draw|winner)|kbc|lottery)\W+(\w+\W+){0,10}(₹|rs\.?|inr|lakh|crore|prize|reward|gift|iphone|car)|"
       r"claim\W+(\w+\W+){0,3}(prize|reward|gift|cashback|refund)",
       "You cannot win a contest you did not enter, and a real prize never needs you to pay or share a PIN first.",
       "Ignore it. Do not pay any 'processing' or 'tax' fee."),
    _p("job_task_scam", "job", "Easy online money for liking videos / simple tasks", 0.8,
       r"(part[\s-]*time|work\s+from\s+home|wfh|online\s+job)\W+(\w+\W+){0,10}(earn|income|salary|₹|rs\.?|per\s+day|daily)|"
       r"(like|subscribe|rate|review)\W+(\w+\W+){0,4}(video|youtube|product|hotel|restaurant)s?\W+(\w+\W+){0,6}(earn|paid|₹|rs\.?)|task\W+(\w+\W+){0,6}(telegram|whatsapp)",
       "Paid-for-simple-tasks offers are a common advance-fee and 'task' scam that ends in a request to deposit money.",
       "Do not deposit any money to 'unlock' tasks or withdrawals. A real employer never asks you to pay."),
    _p("loan_app", "loan", "Instant loan with no documents / pre-approved loan link", 0.65,
       r"(instant|quick|pre[\s-]*approved)\W+(\w+\W+){0,3}loan\W+(\w+\W+){0,10}(without|no)\W+(\w+\W+){0,2}(document|cibil|kyc|income)|pre[\s-]*approved\W+loan\W+(\w+\W+){0,8}(click|download|apply|link)",
       "Illegal loan apps harvest contacts and photos and then harass people. Real lenders do not pre-approve strangers by SMS link.",
       "Borrow only from lenders listed on the RBI website. Do not install apps from a link."),
    _p("digital_arrest", "authority", "Police / CBI / customs / TRAI says you are under 'digital arrest'", 0.95,
       r"digital\s+arrest|(cbi|ed|enforcement\s+directorate|police|customs|narcotics|ncb|trai|cyber\s*(crime|cell)|court)\W+(\w+\W+){0,12}(arrest|warrant|case\s+(has\s+been\s+)?(registered|filed)|parcel\W+(\w+\W+){0,4}(drugs|illegal|passport)|money\s+laundering)|"
       r"(do\s+not|don'?t)\s+(disconnect|cut)\W+(\w+\W+){0,3}(video\s+)?call|stay\s+on\s+(the\s+)?(video\s+)?call",
       "No Indian agency arrests anyone by video call or asks them to stay on a call and move money. 'Digital arrest' does not exist in law.",
       "Hang up. Call 1930 and tell someone you trust. Never transfer money to a 'safe' account."),
    _p("sim_block_trai", "authority", "Your SIM / number will be blocked (TRAI / DoT)", 0.8,
       r"(sim|mobile\s+number|phone\s+number|mobile\s+connection)\W+(\w+\W+){0,8}(will\s+be|is\s+being)\W+(\w+\W+){0,2}(block|disconnect|deactivat|suspend)|(trai|dot|telecom)\W+(\w+\W+){0,8}(disconnect|block|illegal)",
       "Telecom regulators do not block SIMs through a call or message that asks you to press a key or share details.",
       "Check your status with your operator's official app. Report the call on Sanchar Saathi (Chakshu)."),
    _p("income_tax_refund", "tax", "Income-tax refund waiting / click to claim", 0.75,
       r"(income[\s-]*tax|it\s+department|itr)\W+(\w+\W+){0,10}(refund|credited|claim|pending)|refund\W+(\w+\W+){0,6}(₹|rs\.?)\s*[\d,]+\W+(\w+\W+){0,10}(click|link|claim|verify)",
       "Refunds are paid to the bank account already on your tax return. The department does not ask you to claim one through a link.",
       "Check your refund status only by logging in to the official income-tax e-filing portal."),
    _p("credential_request", "credentials", "Asks you to share an OTP / CVV / PIN / password", 0.9,
       r"(share|send|give|tell|provide|enter|reply\s+with)\W+(\w+\W+){0,4}(otp|one[\s-]*time\s+password|cvv|card\s+number|pin|password|net\s*banking\s+(id|password)|aadhaar\s+number)\b",
       "An OTP, CVV or PIN is a key to your money. No bank, government office or company will ask you to read it out.",
       "Never share it, whoever says they are calling. If you did, call your bank and 1930 now.", guard_negation=True),
    _p("remote_access_app", "remote_access", "Asks you to install a remote-control app", 0.9,
       r"(install|download|open)\W+(\w+\W+){0,4}(anydesk|team\s*viewer|quick\s*support|ammyy|rustdesk|airdroid|screen\s*share|apk)\b",
       "Remote-control apps let the caller see your screen and your OTPs and move money on your behalf.",
       "Do not install it. If you did, uninstall it, switch off the internet and call your bank and 1930.", guard_negation=True),
    _p("apk_link", "malware", "Asks you to install an app from a link (.apk)", 0.8,
       r"\b[\w./:-]+\.apk\b|install\W+(\w+\W+){0,4}(this\s+)?app\W+(\w+\W+){0,6}(link|below|click)",
       "Apps from a link (outside the Play Store / App Store) are how banking trojans are delivered.",
       "Install apps only from the official store, from the publisher you expect."),
    _p("urgency", "pressure", "Pressure: act now or lose something", 0.35,
       r"(within|in|before)\W+(the\s+)?(next\s+)?\d+\s*(hours?|hrs?|minutes?|mins?)|(immediately|urgent(ly)?|last\s+(warning|chance|reminder)|final\s+notice|act\s+now|today\s+only|expires?\s+today)",
       "Scammers rush you so you do not stop to check.",
       "Pause. A real problem can wait ten minutes while you check through an official channel."),
    _p("generic_greeting", "pressure", "Generic greeting ('Dear customer')", 0.15,
       r"dear\s+(customer|user|valued\s+customer|account\s+holder|sir/?madam)",
       "A message from your own bank normally uses your name.",
       "Treat messages that do not know who you are with extra care."),
)

CATEGORY_ADVICE = {
    "upi": "Open your UPI app yourself and look at the real requests. You never need a PIN to receive money.",
    "kyc": "Do your KYC only in your bank's own app, on its website typed in by hand, or at a branch.",
    "authority": "No agency arrests or fines people over a call or video call. Hang up and call 1930 if money is involved.",
    "credentials": "Never share an OTP, CVV, PIN or password — with anyone, for any reason.",
}

_NEGATION = re.compile(r"(do\s+not|don'?t|dont|never|not\s+to|no\s+one\s+will|nobody\s+will|should\s+not|must\s+not|avoid)\W+(\w+\W+){0,3}$", I)


def _first_unnegated(pat: Pattern, body: str) -> Optional[re.Match]:
    for m in pat.regex.finditer(body):
        if pat.guard_negation and _NEGATION.search(body[max(0, m.start() - 40):m.start()]):
            continue
        return m
    return None


_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+|\b(?:bit\.ly|tinyurl\.com|cutt\.ly|is\.gd|t\.co|rb\.gy|shorturl\.at|goo\.gl|ow\.ly|tiny\.cc|wa\.me)/[^\s<>\"')\]]+|\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:com|in|co\.in|net|org|info|xyz|top|online|site|club|shop|link|cc|tk|ml|ga|cf|gq|app|live|click)\b[^\s<>\"')\]]*", I)
_SHORTENERS = ("bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "rb.gy", "shorturl.at", "goo.gl", "ow.ly", "tiny.cc", "wa.me")


@lru_cache(maxsize=1)
def _brand_mentions() -> list[tuple[re.Pattern, str]]:
    """``(word-boundary regex, brand name)`` for brands whose name or key is long enough to be unambiguous in running text."""
    out = []
    for b in CURATED_BRANDS:
        names = {b.name.lower(), b.key.lower()}
        for n in names:
            if len(n) >= 5:
                out.append((re.compile(r"\b" + re.escape(n) + r"\b", re.I), b.name))
    return out


class TextMatch(BaseModel):
    id: str
    category: str
    label: str
    weight: float
    evidence: str = Field(..., description="The words of the message that triggered it")
    why: str
    advice: str


class TextUrl(BaseModel):
    url: str
    host: Optional[str] = None
    shortener: bool = False
    brand_check: Optional[BrandCheck] = None
    note: Optional[str] = None


class TextAnalysis(BaseModel):
    risk: str = Field(..., description="none | low | medium | high — the strongest red flag plus a bonus per extra category")
    score: float
    matches: list[TextMatch] = Field(default_factory=list)
    urls: list[TextUrl] = Field(default_factory=list)
    advice: list[str] = Field(default_factory=list)
    arithmetic: str = Field("", description="How the score was computed, so it can be checked by hand")
    limits: list[str] = Field(default_factory=list)
    language: str = "en"
    truncated: bool = False


MAX_CHARS = 8000
EXTRA_CATEGORY_BONUS = 0.05
BRAND_LINK_WEIGHT = 0.7
SHORTENER_WEIGHT = 0.25


def _snippet(text: str, m: re.Match, pad: int = 25) -> str:
    a, b = max(0, m.start() - pad), min(len(text), m.end() + pad)
    return re.sub(r"\s+", " ", text[a:b]).strip()


def _label(score: float) -> str:
    return "high" if score >= 0.65 else "medium" if score >= 0.4 else "low" if score >= 0.2 else "none"


def analyze_text(text: str, index: Optional[BrandIndex] = None) -> TextAnalysis:
    """Read a message and report which known scam patterns it resembles (see the module docstring for what that means)."""
    raw = text or ""
    truncated = len(raw) > MAX_CHARS
    body = raw[:MAX_CHARS]
    matches: list[TextMatch] = []
    for pat in PATTERNS:
        m = _first_unnegated(pat, body)
        if m:
            matches.append(TextMatch(id=pat.id, category=pat.category, label=pat.label, weight=pat.weight, evidence=_snippet(body, m),
                                     why=pat.why, advice=pat.advice))

    urls: list[TextUrl] = []
    seen: set[str] = set()
    index = index or BrandIndex.build()
    for found in _URL.findall(body)[:10]:
        url = found.rstrip(".,;:!?")
        if url.lower() in seen:
            continue
        seen.add(url.lower())
        target = canonicalize(url if "://" in url else "http://" + url, TargetType.URL)
        if not target.valid or not target.host:
            continue
        host = target.host
        short = any(host == s or host.endswith("." + s) for s in _SHORTENERS)
        check = assess_lookalike(host, index)
        note = None
        if check.status == "lookalike" and check.match:
            note = f"Imitates {check.match.brand}; the real site is {check.match.brand_domain}."
            matches.append(TextMatch(id="lookalike_link", category="link", label=f"A link that imitates {check.match.brand}", weight=BRAND_LINK_WEIGHT,
                                     evidence=host, why="The link's domain is built to look like a real brand's, but it is not that brand's domain.",
                                     advice=f"The real site is {check.match.brand_domain}. Type it yourself instead of tapping the link."))
        elif short:
            note = "A link shortener hides where the link really goes."
            matches.append(TextMatch(id="link_shortener", category="link", label="A shortened link hides the real destination", weight=SHORTENER_WEIGHT,
                                     evidence=host, why="Scam messages often use short links so you cannot see the real address.",
                                     advice="Do not open links you were not expecting, especially short ones."))
        urls.append(TextUrl(url=url[:300], host=host, shortener=short, brand_check=check if check.status != "no_match" else None, note=note))

    # a protected brand is named in the text but a link goes somewhere that is not that brand's own domain
    mentioned = sorted({name for rx, name in _brand_mentions() if rx.search(body)})
    if mentioned and urls:
        for u in urls:
            check = u.brand_check
            if check is not None and check.status == "official":
                continue                                                  # the link is a brand's own domain (the mentioned one or not)
            names = ", ".join(mentioned[:2])
            matches.append(TextMatch(id="brand_with_foreign_link", category="link", label=f"Names {names} but links to a different site", weight=0.6,
                                     evidence=f"{names} … {u.host}", why="A message from a real brand links to that brand's own domain.",
                                     advice="Open the brand's app or type its address yourself."))
            break

    # score = strongest red flag + a small bonus for each additional category (capped at 1.0)
    by_cat: dict[str, float] = {}
    for m in matches:
        by_cat[m.category] = max(by_cat.get(m.category, 0.0), m.weight)
    if by_cat:
        ordered = sorted(by_cat.items(), key=lambda kv: -kv[1])
        score = min(1.0, ordered[0][1] + EXTRA_CATEGORY_BONUS * (len(ordered) - 1))
        arithmetic = f"strongest: {ordered[0][0]} {ordered[0][1]:.2f}" + (f" + {EXTRA_CATEGORY_BONUS:.2f} x {len(ordered) - 1} other categories" if len(ordered) > 1 else "") + f" = {score:.2f}"
    else:
        score, arithmetic = 0.0, "no known pattern matched"
    risk = _label(score)

    matches.sort(key=lambda m: -m.weight)
    advice: list[str] = []
    for m in matches:
        for line in (CATEGORY_ADVICE.get(m.category), m.advice):
            if line and line not in advice:
                advice.append(line)
        if len(advice) >= 4:
            break
    if risk in ("medium", "high") and "If you lost money or shared a code, call 1930 now and tell your bank." not in advice:
        advice.append("If you lost money or shared a code, call 1930 now and tell your bank.")
    limits = ["This checks the words against known scam patterns. It is not a verdict.",
              "No match does not mean safe: scammers rewrite their scripts. A match does not mean fraud: real banks use some of these words.",
              "When in doubt, contact the organisation yourself using a number or app you already trust."]
    return TextAnalysis(risk=risk, score=round(score, 2), matches=matches[:8], urls=urls, advice=advice[:5], arithmetic=arithmetic,
                        limits=limits, truncated=truncated)

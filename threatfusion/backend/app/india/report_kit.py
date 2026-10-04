"""
Reporting helpers for India (B16)
=================================

When something looks like a scam the next question is "who do I tell?".  This module builds a **report kit**: a pre-filled,
copy-ready description of what was seen, and the right official channels with *when to use each*.

**ThreatFusion submits nothing for you.**  It cannot and should not file a police complaint on your behalf: it prepares the
text, you read it, add what only you know (what you lost, when), and file it yourself.  The text contains only what ThreatFusion
itself observed (the host name, the time, the reasons it gave) — never your name, phone number or account details; a person
who has lost money needs the *speed* of the helpline, not a form.

Channels (check the official site for current details — they were **not** verified live when this was written):

* **1930** — the national cyber-fraud helpline: call at once if money has left your account (early reports can still stop it).
* **cybercrime.gov.in** — the National Cyber Crime Reporting Portal: file a complaint for any cybercrime, incl. financial fraud.
* **Sanchar Saathi — Chakshu** (sancharsaathi.gov.in): report a suspected fraud call, SMS or WhatsApp message to the Department
  of Telecommunications.
* **CERT-In** (cert-in.org.in, incident@cert-in.org.in): for organisations and for phishing sites impersonating Indian entities.
* **Your bank / UPI app**: block the card or UPI handle and dispute the transaction using the *official* number or the app.
* **The impersonated brand**: most large brands have a "report phishing" mailbox on their official site.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field

IST = timezone(timedelta(hours=5, minutes=30), "IST")

ReportKind = Literal["website", "message", "call"]


class Channel(BaseModel):
    id: str
    name: str
    how: str = Field(..., description="The address or number to use")
    url: Optional[str] = None
    use_when: str
    note: Optional[str] = None


class ReportKit(BaseModel):
    kind: ReportKind
    summary_text: str = Field(..., description="Copy-ready description of what ThreatFusion saw — no personal data")
    steps: list[str]
    channels: list[Channel]
    reminders: list[str]
    generated_at: str


CHANNELS: dict[str, Channel] = {
    "helpline_1930": Channel(id="helpline_1930", name="National Cyber Crime Helpline", how="Call 1930", url=None,
                             use_when="Money has left your account, or you shared an OTP / PIN / card details. Call first — speed matters.",
                             note="Have the transaction id, amount, time and the account involved ready."),
    "cybercrime_portal": Channel(id="cybercrime_portal", name="National Cyber Crime Reporting Portal", how="cybercrime.gov.in", url="https://cybercrime.gov.in",
                                 use_when="You want to file a formal complaint about any cybercrime, including online financial fraud and scam messages.",
                                 note="Keep screenshots, the message text, the link and any transaction details."),
    "chakshu": Channel(id="chakshu", name="Sanchar Saathi — Chakshu", how="sancharsaathi.gov.in", url="https://sancharsaathi.gov.in",
                       use_when="A phone call, SMS or WhatsApp message tried to scam you (even if you lost nothing) — report the number and message.",
                       note="Run by the Department of Telecommunications; helps get fraud numbers disconnected."),
    "cert_in": Channel(id="cert_in", name="CERT-In incident reporting", how="incident@cert-in.org.in", url="https://www.cert-in.org.in",
                       use_when="A phishing website, or an attack on an organisation, especially one impersonating an Indian bank or government body.",
                       note="Include the full URL and a screenshot; they coordinate takedowns."),
    "your_bank": Channel(id="your_bank", name="Your bank / UPI app", how="the number printed on your card or inside the official app", url=None,
                         use_when="You shared card or UPI details, or a payment you did not make has left your account: block the card / UPI handle and raise a dispute.",
                         note="Use the official app or the number on your card — not a number from the message."),
}


def _brand_channel(brand: str, domain: str) -> Channel:
    return Channel(id="brand", name=f"{brand} (the impersonated brand)", how=f"the 'report phishing' page or support mailbox on {domain}", url=f"https://{domain}",
                   use_when=f"The site or message pretends to be {brand}. Tell them so they can warn customers and request a takedown.",
                   note="Open their site by typing the address yourself.")


def build_report_kit(kind: ReportKind, *, host: Optional[str] = None, url: Optional[str] = None, reasons: Optional[list[str]] = None,
                     brand: Optional[str] = None, brand_domain: Optional[str] = None, scan_id: Optional[str] = None,
                     message_excerpt: Optional[str] = None, lost_money: bool = False, now: Optional[datetime] = None) -> ReportKit:
    """Prepare a report. ``lost_money`` puts the helpline first and adds the time-critical steps."""
    now = (now or datetime.now(timezone.utc)).astimezone(IST)
    stamp = now.strftime("%d %b %Y, %I:%M %p IST")
    lines = [f"I am reporting a suspected {'scam website' if kind == 'website' else 'scam message' if kind == 'message' else 'scam call'} (seen {stamp})."]
    if kind == "website" and (host or url):
        lines.append(f"Website: {url or host}")
    if brand:
        lines.append(f"It appears to impersonate: {brand}" + (f" (the real site is {brand_domain})." if brand_domain else "."))
    for r in (reasons or [])[:4]:
        lines.append(f"- Observed: {r}")
    if message_excerpt:
        lines.append("Message (excerpt): " + " ".join(message_excerpt.split())[:300])
    lines.append("A copy of the evidence (screenshots / message / link) is attached or available on request." + (f" Reference: ThreatFusion scan {scan_id}." if scan_id else ""))
    lines.append("I have [not] lost money. [Add: amount, date and time, transaction id, the account / UPI handle involved.]")
    summary = "\n".join(lines)

    steps = []
    if lost_money:
        steps += ["Call 1930 now and tell them the amount, time and transaction id — the sooner, the better the chance of stopping the transfer.",
                  "Call your bank on its official number (or use its app) and block the card / UPI handle.",
                  "Do not delete the message or the call log; take screenshots.",
                  "File the complaint on cybercrime.gov.in using the text above (add the details only you know)."]
    else:
        steps += ["Do not tap links, call back, or share any code or PIN.",
                  "Take a screenshot and keep the message or link as it is.",
                  "Report it on the portals below using the text above.",
                  "If you already entered a password, change it now from the official site or app."]
    if kind in ("message", "call"):
        steps.insert(2, "Report the number on Sanchar Saathi (Chakshu) so it can be blocked for others.")

    order = ["helpline_1930", "your_bank", "cybercrime_portal", "chakshu", "cert_in"] if lost_money else \
            (["chakshu", "cybercrime_portal", "cert_in"] if kind in ("message", "call") else ["cybercrime_portal", "cert_in", "chakshu"])
    channels = [CHANNELS[i] for i in order]
    if brand and brand_domain:
        channels.append(_brand_channel(brand, brand_domain))
    return ReportKit(
        kind=kind, summary_text=summary, steps=steps, channels=channels, generated_at=now.isoformat(timespec="seconds"),
        reminders=["ThreatFusion does not submit anything for you: copy the text, add what only you know, and file it yourself.",
                   "The text contains only what ThreatFusion observed; it has no personal data. Add your own details yourself, and only on the official sites.",
                   "Contact details change: check the official site for the current number or address before relying on them."])

"""
Protected brands and the index used to find look-alikes of them (B4)
===================================================================

Impersonating a brand is the dominant phishing tactic, so the scanner keeps a list of *protected brands* and checks every
scanned domain against it:

* a **curated list** — global brands plus a curated **India list** (banks, UPI/payment apps, IRCTC, India Post, UIDAI,
  Income Tax, EPFO, DigiLocker, e-commerce, telecom) — each with its *official registered domains* (so the genuine
  site and its subdomains are never flagged) and the *keywords* that name the brand in a domain;
* optionally the top of the **Tranco** popularity list (``BrandIndex.build(popular=…)``; the downloader arrives with B2),
  used conservatively — only for confusable-character and long-name typo matches, never for containment, because an
  ordinary word that is also a popular site name ("weather") would otherwise flood the results with false positives.

The index stores every brand label in its **canonical form** (``ml/confusables.canonical``: TR39 skeleton, leetspeak,
``rn`` → ``m``) so that ``paypa1``, ``pаypal`` (Cyrillic) and ``paypal`` meet in one dictionary lookup, and a bigram
inverted index so edit-distance candidates are found without comparing against every brand (the check runs in the fast
tier: milliseconds even with thousands of brands).

The official-domain data below is conservative on purpose: a wrong entry would hide a lookalike, a missing one only costs
a lower-confidence ``same_name_other_tld`` note.  Domains where *anyone* can publish a page (``github.io``,
``myshopify.com``, ``amazonaws.com``, ``sharepoint.com``…) are deliberately **not** listed as official: a brand name in
the subdomain of one of those (``paypal-login.github.io``) is exactly the kind of thing this module should flag.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from app.ml import confusables as cf

# Words phishing pages put next to a brand name ("brand-login", "secure-brand", "brandsupport", …).
RISK_WORDS = frozenset("""
login signin sign-in logon secure security verify verification validate account accounts update upgrade support help
helpdesk care customercare service services billing payment payments pay wallet refund refunds kyc otp alert alerts
online netbanking banking bank card cards reward rewards offer offers claim unlock recover recovery reset auth portal
official india indian ticket tickets booking tracking delivery recharge bonus gift lottery prize cashback voucher
confirm confirmation notice suspended limited restore mobile app apps customer web id access
deal deals sale sales discount coupon coupons
""".split())

# Edit-distance matching is the noisiest rule (``phase`` is one edit from ``chase``, ``stream`` from ``steam``), so it is
# restricted: curated brands need 6+ characters for one edit and 9+ for two; popular domains 9+ characters, top-2000 only.
# Shorter names are still caught by the exact confusable / keyword / subdomain rules, which are far more specific.
_MIN_TYPO_LENGTH = 6
MIN_CONTAINMENT_LENGTH = 5      # substring containment only for brand strings at least this long
_POPULAR_TYPO_MIN_LENGTH = 9
_POPULAR_TYPO_MAX_RANK = 2000


@dataclass(frozen=True)
class Brand:
    key: str                              # the brand's main label, e.g. "paypal"
    name: str                             # display name, e.g. "PayPal"
    domains: tuple[str, ...]              # official registered domains (never flagged, subdomains included)
    sector: str                           # payments | bank | gov | ecommerce | telecom | tech | social | logistics | crypto | media | travel
    country: Optional[str]                # "IN" for the India list, None for global
    keywords: tuple[str, ...] = ()        # other labels that name the brand ("onlinesbi", "aadhaar", …)
    source: str = "curated"               # curated | popular
    rank: Optional[int] = None            # Tranco rank for popular brands

    @property
    def labels(self) -> tuple[str, ...]:
        return (self.key, *self.keywords)


def _b(key, name, sector, country, domains, keywords="") -> Brand:
    return Brand(key=key, name=name, domains=tuple(domains.split()), sector=sector, country=country,
                 keywords=tuple(keywords.split()))


# ── global brands ───────────────────────────────────────────────────────────
_GLOBAL = [
    _b("paypal", "PayPal", "payments", None, "paypal.com paypal.me paypalobjects.com"),
    _b("google", "Google", "tech", None, "google.com google.co.in gmail.com googlemail.com goo.gl", "gmail"),
    _b("microsoft", "Microsoft", "tech", None,
       "microsoft.com live.com office.com outlook.com microsoftonline.com office365.com windows.com azure.com bing.com "
       "msn.com skype.com xbox.com onedrive.com", "office365 outlook onedrive"),
    _b("apple", "Apple", "tech", None, "apple.com icloud.com", "icloud appleid"),
    _b("amazon", "Amazon", "ecommerce", None,
       "amazon.com amazon.in amazon.co.uk amazon.de amazon.ca amazon.com.au primevideo.com amzn.to amzn.in",
       "amazonprime"),
    _b("facebook", "Facebook", "social", None, "facebook.com fb.com fb.me meta.com messenger.com"),
    _b("instagram", "Instagram", "social", None, "instagram.com"),
    _b("whatsapp", "WhatsApp", "social", None, "whatsapp.com whatsapp.net wa.me"),
    _b("netflix", "Netflix", "media", None, "netflix.com"),
    _b("linkedin", "LinkedIn", "social", None, "linkedin.com lnkd.in"),
    _b("twitter", "Twitter / X", "social", None, "twitter.com x.com t.co"),
    _b("dropbox", "Dropbox", "tech", None, "dropbox.com"),
    _b("docusign", "DocuSign", "tech", None, "docusign.com docusign.net"),
    _b("adobe", "Adobe", "tech", None, "adobe.com"),
    _b("dhl", "DHL", "logistics", None, "dhl.com dhl.de dhl.co.in"),
    _b("fedex", "FedEx", "logistics", None, "fedex.com"),
    _b("ups", "UPS", "logistics", None, "ups.com"),
    _b("usps", "USPS", "logistics", None, "usps.com"),
    _b("chase", "Chase", "bank", None, "chase.com jpmorganchase.com jpmorgan.com"),
    _b("wellsfargo", "Wells Fargo", "bank", None, "wellsfargo.com"),
    _b("bankofamerica", "Bank of America", "bank", None, "bankofamerica.com"),
    _b("citibank", "Citibank", "bank", None, "citibank.com citi.com citibank.co.in", "citi"),
    _b("hsbc", "HSBC", "bank", None, "hsbc.com hsbc.co.in hsbc.co.uk"),
    _b("standardchartered", "Standard Chartered", "bank", None, "sc.com standardchartered.com"),
    _b("steam", "Steam", "tech", None, "steampowered.com steamcommunity.com", "steampowered steamcommunity"),
    _b("binance", "Binance", "crypto", None, "binance.com"),
    _b("coinbase", "Coinbase", "crypto", None, "coinbase.com"),
    _b("metamask", "MetaMask", "crypto", None, "metamask.io"),
    _b("trustwallet", "Trust Wallet", "crypto", None, "trustwallet.com"),
    _b("blockchain", "Blockchain.com", "crypto", None, "blockchain.com"),
    _b("kraken", "Kraken", "crypto", None, "kraken.com"),
    _b("ledger", "Ledger", "crypto", None, "ledger.com"),
    _b("telegram", "Telegram", "social", None, "telegram.org t.me telegram.me"),
    _b("spotify", "Spotify", "media", None, "spotify.com"),
    _b("zoom", "Zoom", "tech", None, "zoom.us"),
    _b("ebay", "eBay", "ecommerce", None, "ebay.com ebay.in"),
    _b("github", "GitHub", "tech", None, "github.com"),
    _b("shopify", "Shopify", "ecommerce", None, "shopify.com"),
    _b("yahoo", "Yahoo", "tech", None, "yahoo.com"),
    _b("airbnb", "Airbnb", "travel", None, "airbnb.com airbnb.co.in"),
    _b("uber", "Uber", "travel", None, "uber.com"),
    _b("booking", "Booking.com", "travel", None, "booking.com"),
    _b("aliexpress", "AliExpress", "ecommerce", None, "aliexpress.com"),
    _b("walmart", "Walmart", "ecommerce", None, "walmart.com"),
    _b("tiktok", "TikTok", "social", None, "tiktok.com"),
    _b("snapchat", "Snapchat", "social", None, "snapchat.com"),
    _b("roblox", "Roblox", "tech", None, "roblox.com"),
    _b("epicgames", "Epic Games", "tech", None, "epicgames.com"),
]

# ── curated India list ──────────────────────────────────────────────────────
_INDIA = [
    # banks & financial
    _b("sbi", "State Bank of India", "bank", "IN", "sbi.co.in onlinesbi.sbi onlinesbi.com sbicard.com sbilife.co.in sbimf.com",
       "onlinesbi sbicard sbilife sbimf statebankofindia"),
    _b("hdfcbank", "HDFC Bank", "bank", "IN", "hdfcbank.com hdfc.com hdfclife.com hdfcsec.com hdfcergo.com",
       "hdfc hdfclife hdfcsec hdfcergo"),
    _b("icicibank", "ICICI Bank", "bank", "IN", "icicibank.com icicidirect.com icicilombard.com iciciprulife.com",
       "icici icicidirect icicilombard iciciprulife"),
    _b("axisbank", "Axis Bank", "bank", "IN", "axisbank.com axismf.com axisdirect.in", "axismf axisdirect"),
    _b("kotak", "Kotak Mahindra Bank", "bank", "IN", "kotak.com kotakbank.com kotaksecurities.com", "kotakbank kotaksecurities"),
    _b("pnbindia", "Punjab National Bank", "bank", "IN", "pnbindia.in netpnb.com", "pnb netpnb"),
    _b("bankofbaroda", "Bank of Baroda", "bank", "IN", "bankofbaroda.in bankofbaroda.com bobibanking.com", "bobibanking"),
    _b("canarabank", "Canara Bank", "bank", "IN", "canarabank.com", "canara"),
    _b("unionbankofindia", "Union Bank of India", "bank", "IN", "unionbankofindia.co.in unionbankonline.co.in",
       "unionbank unionbankonline"),
    _b("idfcfirstbank", "IDFC FIRST Bank", "bank", "IN", "idfcfirstbank.com", "idfcbank idfcfirst"),
    _b("yesbank", "Yes Bank", "bank", "IN", "yesbank.in"),
    _b("indusind", "IndusInd Bank", "bank", "IN", "indusind.com", "indusindbank"),
    _b("bankofindia", "Bank of India", "bank", "IN", "bankofindia.co.in"),
    _b("indianbank", "Indian Bank", "bank", "IN", "indianbank.in"),
    _b("centralbankofindia", "Central Bank of India", "bank", "IN", "centralbankofindia.co.in"),
    _b("federalbank", "Federal Bank", "bank", "IN", "federalbank.co.in"),
    _b("rblbank", "RBL Bank", "bank", "IN", "rblbank.com"),
    _b("idbibank", "IDBI Bank", "bank", "IN", "idbibank.in idbi.com", "idbi"),
    _b("licindia", "Life Insurance Corporation of India", "bank", "IN", "licindia.in", "lic"),
    _b("bajajfinserv", "Bajaj Finserv", "bank", "IN", "bajajfinserv.in", "bajajfinance"),
    _b("paytm", "Paytm", "payments", "IN", "paytm.com paytmbank.com", "paytmbank"),
    _b("phonepe", "PhonePe", "payments", "IN", "phonepe.com"),
    _b("razorpay", "Razorpay", "payments", "IN", "razorpay.com"),
    _b("npci", "NPCI / BHIM UPI", "payments", "IN", "npci.org.in bhimupi.org.in", "bhim bhimupi"),
    _b("mobikwik", "MobiKwik", "payments", "IN", "mobikwik.com"),
    _b("freecharge", "Freecharge", "payments", "IN", "freecharge.in"),
    _b("zerodha", "Zerodha", "bank", "IN", "zerodha.com"),
    _b("groww", "Groww", "bank", "IN", "groww.in"),
    _b("upstox", "Upstox", "bank", "IN", "upstox.com"),
    _b("nsdl", "NSDL", "bank", "IN", "nsdl.co.in"),
    _b("rbi", "Reserve Bank of India", "gov", "IN", "rbi.org.in"),
    # government
    _b("irctc", "IRCTC", "gov", "IN", "irctc.co.in irctc.com", "irctctourism"),
    _b("indiapost", "India Post", "gov", "IN", "indiapost.gov.in", "indiapostgdsonline"),
    _b("uidai", "UIDAI (Aadhaar)", "gov", "IN", "uidai.gov.in", "aadhaar aadhar myaadhaar"),
    _b("incometax", "Income Tax Department", "gov", "IN", "incometax.gov.in incometaxindia.gov.in",
       "incometaxindia incometaxefiling"),
    _b("epfo", "EPFO", "gov", "IN", "epfindia.gov.in epfindia.com", "epfindia"),
    _b("digilocker", "DigiLocker", "gov", "IN", "digilocker.gov.in"),
    _b("gst", "GST Portal", "gov", "IN", "gst.gov.in"),
    _b("passportindia", "Passport Seva", "gov", "IN", "passportindia.gov.in", "passportseva"),
    _b("parivahan", "Parivahan (Transport)", "gov", "IN", "parivahan.gov.in", "mparivahan"),
    _b("umang", "UMANG", "gov", "IN", "umang.gov.in"),
    _b("cowin", "CoWIN", "gov", "IN", "cowin.gov.in"),
    _b("mygov", "MyGov", "gov", "IN", "mygov.in"),
    _b("aarogyasetu", "Aarogya Setu", "gov", "IN", "aarogyasetu.gov.in"),
    # e-commerce & consumer
    _b("flipkart", "Flipkart", "ecommerce", "IN", "flipkart.com"),
    _b("myntra", "Myntra", "ecommerce", "IN", "myntra.com"),
    _b("meesho", "Meesho", "ecommerce", "IN", "meesho.com"),
    _b("swiggy", "Swiggy", "ecommerce", "IN", "swiggy.com"),
    _b("zomato", "Zomato", "ecommerce", "IN", "zomato.com"),
    _b("bigbasket", "BigBasket", "ecommerce", "IN", "bigbasket.com"),
    _b("ajio", "Ajio", "ecommerce", "IN", "ajio.com"),
    _b("nykaa", "Nykaa", "ecommerce", "IN", "nykaa.com"),
    _b("snapdeal", "Snapdeal", "ecommerce", "IN", "snapdeal.com"),
    _b("tataneu", "Tata Neu", "ecommerce", "IN", "tataneu.com"),
    _b("croma", "Croma", "ecommerce", "IN", "croma.com"),
    _b("blinkit", "Blinkit", "ecommerce", "IN", "blinkit.com"),
    _b("jiomart", "JioMart", "ecommerce", "IN", "jiomart.com"),
    _b("dream11", "Dream11", "ecommerce", "IN", "dream11.com"),
    _b("bookmyshow", "BookMyShow", "travel", "IN", "bookmyshow.com"),
    _b("makemytrip", "MakeMyTrip", "travel", "IN", "makemytrip.com"),
    _b("goibibo", "Goibibo", "travel", "IN", "goibibo.com"),
    _b("redbus", "redBus", "travel", "IN", "redbus.in"),
    _b("olacabs", "Ola", "travel", "IN", "olacabs.com", "ola"),
    # telecom
    _b("airtel", "Airtel", "telecom", "IN", "airtel.in airtel.com", "airtelpayments"),
    _b("jio", "Jio", "telecom", "IN", "jio.com", "jiofiber"),
    _b("vodafoneidea", "Vodafone Idea (Vi)", "telecom", "IN", "myvi.in vodafoneidea.com", "myvi"),
    _b("bsnl", "BSNL", "telecom", "IN", "bsnl.co.in"),
    _b("mtnl", "MTNL", "telecom", "IN", "mtnl.in"),
]

CURATED_BRANDS: tuple[Brand, ...] = tuple(_GLOBAL + _INDIA)

# Third parties cannot register under these: any registered domain below them is a genuine government site.
GOVERNMENT_SUFFIXES = ("gov.in", "nic.in", "gov.uk", "gov.au", "gov")


# ── edit distance ───────────────────────────────────────────────────────────
def edit_distance(a: str, b: str, max_distance: int = 2) -> int:
    """Optimal-string-alignment (Damerau-Levenshtein) distance; returns ``max_distance + 1`` if it exceeds the limit."""
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    if a == b:
        return 0
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        row_min = cur[0]
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)                      # transposition
            row_min = min(row_min, cur[j])
        if row_min > max_distance:
            return max_distance + 1
        prev2, prev = prev, cur
    return min(prev[len(b)], max_distance + 1)


def _deletes(word: str, max_distance: int) -> set[str]:
    """``word`` and every string reachable by deleting up to ``max_distance`` characters (the SymSpell neighbourhood)."""
    out = {word}
    frontier = {word}
    for _ in range(max_distance):
        frontier = {w[:i] + w[i + 1:] for w in frontier for i in range(len(w))}
        out |= frontier
    return out


def typo_budget(brand: Brand) -> int:
    """The largest edit distance at which ``brand`` can be matched as a typo (0 = never)."""
    n = len(brand.key)
    if brand.source == "curated":
        return 2 if n >= 9 else 1 if n >= _MIN_TYPO_LENGTH else 0
    return 1 if n >= _POPULAR_TYPO_MIN_LENGTH and (brand.rank or 10 ** 9) <= _POPULAR_TYPO_MAX_RANK else 0


class BrandIndex:
    """Canonical-label dictionary + deletion-neighbourhood typo index over a list of brands (see module docstring).

    Why a deletion index: two strings within edit distance *d* share a string reachable by deleting at most *d* characters
    from each (substitution, insertion, deletion and transposition all do), so candidates come from dictionary lookups —
    never a scan of thousands of brands — and are then confirmed with the exact edit distance.
    """

    def __init__(self, brands: Iterable[Brand]) -> None:
        self.brands: list[Brand] = list(brands)
        self._official: dict[str, Brand] = {}
        self._by_canon: dict[str, list[tuple[Brand, str]]] = {}      # canonical label -> [(brand, original label)]
        self._curated_labels: list[tuple[str, Brand]] = []           # (canonical label, brand) — for keyword/containment
        self._typo: list[tuple[str, Brand]] = []                     # (canonical key, brand) of typo-eligible brands
        self._deletes: dict[str, list[int]] = {}
        self._max_key = 0
        for brand in self.brands:
            for domain in brand.domains:
                self._official.setdefault(domain.lower(), brand)
            for label in brand.labels:
                canon = cf.canonical(label)[0]
                self._by_canon.setdefault(canon, []).append((brand, label))
                if brand.source == "curated":
                    self._curated_labels.append((canon, brand))
            budget = typo_budget(brand)
            if budget:
                canon_key = cf.canonical(brand.key)[0]
                idx = len(self._typo)
                self._typo.append((canon_key, brand))
                self._max_key = max(self._max_key, len(canon_key))
                for variant in _deletes(canon_key, budget):
                    self._deletes.setdefault(variant, []).append(idx)

    @classmethod
    def build(cls, popular: Iterable[tuple[str, int]] = (), limit: int = 5000) -> "BrandIndex":
        """The curated brands plus up to ``limit`` popular domains ``(registered domain, rank)``."""
        brands = list(CURATED_BRANDS)
        curated_domains = {d for b in brands for d in b.domains}
        added = 0
        for domain, rank in popular:
            domain = domain.strip().lower()
            if added >= limit or not domain or domain in curated_domains:
                continue
            label = domain.split(".")[0]
            if len(label) < MIN_CONTAINMENT_LENGTH:
                continue                                              # short names are too noisy to protect
            brands.append(Brand(key=label, name=domain, domains=(domain,), sector="popular", country=None,
                                source="popular", rank=rank))
            added += 1
        return cls(brands)

    # ── queries ────────────────────────────────────────────────────────
    def stats(self) -> dict[str, int]:
        curated = sum(1 for b in self.brands if b.source == "curated")
        return {"curated": curated, "popular": len(self.brands) - curated}

    def official(self, registered_domain: str) -> Optional[Brand]:
        return self._official.get(registered_domain.lower())

    def exact(self, canon: str) -> list[tuple[Brand, str]]:
        return self._by_canon.get(canon, [])

    def curated_labels(self) -> list[tuple[str, Brand]]:
        return self._curated_labels

    def near(self, canon: str) -> list[tuple[Brand, int]]:
        """Typo-eligible brands within their own edit budget of ``canon`` (excluding an exact match), nearest first."""
        if len(canon) < _MIN_TYPO_LENGTH - 1 or len(canon) > self._max_key + 2:      # one letter may be missing
            return []
        candidates: set[int] = set()
        for variant in _deletes(canon, 2):
            candidates.update(self._deletes.get(variant, ()))
        found: list[tuple[Brand, int]] = []
        for idx in candidates:
            key, brand = self._typo[idx]
            budget = typo_budget(brand)
            d = edit_distance(canon, key, budget)
            if 0 < d <= budget:
                found.append((brand, d))
        found.sort(key=lambda bd: (bd[1], bd[0].key))
        return found

    @staticmethod
    def typo_similarity(brand: Brand, distance: int) -> Optional[float]:
        """What an edit-distance match is worth for this brand, or ``None`` if it should not count."""
        if distance < 1 or distance > typo_budget(brand):
            return None
        if brand.source == "curated":
            return 0.90 if distance == 1 else 0.82
        return 0.82

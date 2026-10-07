# ThreatFusion browser extension (Manifest V3)

Checks every page you open against **your own ThreatFusion backend** (on this computer) and warns you about suspicious sites.

## What it does

* **On every top-level navigation** the service worker (`background.js`) asks `POST http://127.0.0.1:8000/scan/fast` for the
  **fast-tier** verdict: local blocklists (OpenPhish, PhishTank), the look-alike-domain check (the real brand's domain is named),
  and the URL-text models. The fast tier is *local*: the backend answers from data it already holds and sends **nothing about the
  page to any third party**.
* A **toolbar badge** shows `!` (suspicious) or `!!` (on a phishing list). There is no badge for "nothing found" — that is not
  a guarantee, so it is never shown as "safe".
* For a look-alike, a listed page or flagged URL text, the content script (`content.js`) shows a **banner** (closed Shadow DOM, so
  the page cannot hide it) with the reason, a *Go back* button and a **Report a mistake** button (a false-positive report that
  goes to the backend's review queue — it is **not** used for anything until a person accepts it), and **outlines password
  fields** on that page.
* The popup (`popup.html`) runs a full scan on demand and shows the host, the verdict, the top three reasons and an **Open in ThreatFusion** link. That link opens the dashboard (`DASHBOARD_URL` in `lib.mjs`, default `http://localhost:5173`) with the scan form pre-filled; it never starts a scan by itself.

## What is sent where

| Data | Goes to | When |
|---|---|---|
| the page's **host name** (default) — or the full URL if you tick *Send full URL* in the popup | your backend on `127.0.0.1:8000` | each navigation (cached 10 min per host) |
| a report (host, your note ≤ 500 chars, the verdict you saw) | your backend, `POST /feedback` | only when you press *Report a mistake* |
| **nothing** | anywhere else | — |

Never checked at all: non-web pages (`chrome://`, `file://`, `about:`), single-label and private names (`localhost`, `*.local`,
`*.lan`, `10.x`, `192.168.x`, …). The content script reads nothing from the page except whether password fields exist.

## Permissions (kept minimal, and why)

| Permission | Why |
|---|---|
| `webNavigation` | to see top-level navigations and start the check |
| `storage` | the API token and your two choices (full URL, auto-check) — this browser profile only |
| `activeTab` | the popup's on-demand scan of the current tab |
| host `127.0.0.1:8000` / `localhost:8000` | to talk to your own backend — no other host |
| content script on `http(s)://*/*` | **the broad one.** Showing the warning banner automatically needs a script on the page. It is inert unless the backend flagged the page, sends nothing, and reads nothing but the presence of password fields. If you prefer, remove the `content_scripts` block from `manifest.json`: you then keep the badge and the popup, and lose the banner |

## Install (developer mode)

1. Start the backend (`python -m uvicorn app.main:app --port 8000` in `backend/`) and print the API token: `python -m app.core.auth`.
2. Chrome → `chrome://extensions` → *Developer mode* → *Load unpacked* → this folder.
3. Open the popup, paste the token under *API token*, *Save* (the field opens by itself until a token is saved).

## Tests

`node --test "extension/tests/*.test.mjs"` (from `threatfusion/`) covers the pure logic in `lib.mjs`: which pages may be checked,
what is sent, when a banner is shown, the badge wording, the cache and the report body. The service worker and content script are
thin wrappers around it and are exercised by loading the extension.

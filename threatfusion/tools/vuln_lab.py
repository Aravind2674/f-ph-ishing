"""
ThreatFusion – Local Vulnerable Lab  (Phase 4 test target)
===========================================================

A deliberately-vulnerable toy web app used to verify the active verification
engine against a *real* HTTP target — safely, on localhost. It is the local
equivalent of standing up OWASP Juice Shop / DVWA, but tiny and dependency-light.

⚠️  FOR LOCAL TESTING ONLY. Never expose this to a network. It intentionally
    reflects unescaped input and emits SQL errors so the verifier has something
    real to confirm.

Endpoints
---------
- ``/search?q=``   reflected XSS   — echoes ``q`` into HTML unescaped.
- ``/user?id=``    SQL injection   — builds an unsanitised SQLite query, so a
                                     ``'`` yields a real SQL error and boolean
                                     payloads change the result set.
- ``/safe?q=``     control         — echoes ``q`` HTML-escaped (not vulnerable).

Run:
    python -m tools.vuln_lab           # serves on http://127.0.0.1:8099
"""

from __future__ import annotations

import html
import sqlite3

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="ThreatFusion Vulnerable Lab (LOCAL TEST ONLY)")

# In-memory demo DB.
_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
_db.executemany("INSERT INTO users VALUES (?, ?)",
                [(1, "alice"), (2, "bob"), (3, "carol")])
_db.commit()


@app.get("/search", response_class=HTMLResponse)
def search(q: str = "") -> str:
    # VULNERABLE: reflects q without escaping.
    return f"<html><body><h1>Results for {q}</h1><p>No items found.</p></body></html>"


@app.get("/safe", response_class=HTMLResponse)
def safe(q: str = "") -> str:
    # SAFE control: q is HTML-escaped.
    return f"<html><body><h1>Results for {html.escape(q)}</h1></body></html>"


@app.get("/user", response_class=HTMLResponse)
def user(id: str = "1") -> str:
    # VULNERABLE: string-built SQL. A lone quote errors; boolean payloads change
    # the number of rows returned.
    query = f"SELECT id, name FROM users WHERE id = '{id}'"
    try:
        rows = _db.execute(query).fetchall()
    except sqlite3.Error as exc:
        # Surfaces a real SQL error string (what error-based detection keys on).
        return f"<html><body>SQLite error: {exc} in query: {query}</body></html>"
    items = "".join(f"<li>{r[0]}: {r[1]}</li>" for r in rows)
    return f"<html><body><ul>{items or '<li>no user</li>'}</ul></body></html>"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8099, log_level="warning")

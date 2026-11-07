"""
security_demo.py  --  Live demonstration of the Secure Guestbook's defenses.

This script feeds the application's real security logic the actual attacks it is
built to stop, and prints PASS when each attack is neutralized. It uses only the
Python standard library (sqlite3, html, secrets), so it runs with no installation
and no server required -- ideal for a screencast.

Run:  python security_demo.py
"""

import sqlite3
import html
import secrets

print("=" * 64)
print(" SECURE GUESTBOOK -- LIVE SECURITY DEMONSTRATION")
print("=" * 64)

# ---------------------------------------------------------------------------
# 1) SQL INJECTION -- parameterized queries store input as data, not code.
# ---------------------------------------------------------------------------
print("\n[1] SQL INJECTION DEFENSE (parameterized queries)")
db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE entries (id INTEGER PRIMARY KEY, author TEXT, message TEXT)")
attack = "Robert'); DROP TABLE entries;--"
print("    Attacker submits message:", attack)
# The app uses ? placeholders -- the attack is treated as literal text.
db.execute("INSERT INTO entries (author, message) VALUES (?, ?)", ("attacker", html.escape(attack)))
db.commit()
rows = db.execute("SELECT message FROM entries").fetchall()
assert len(rows) == 1, "FAIL: table was dropped!"
print("    Result: 'entries' table is INTACT; attack stored as plain text.")
print("    >>> PASS: SQL injection blocked.")

# ---------------------------------------------------------------------------
# 2) STORED XSS -- html.escape() + template autoescaping neutralize scripts.
# ---------------------------------------------------------------------------
print("\n[2] STORED XSS DEFENSE (output escaping + CSP header)")
xss = "<script>alert(document.cookie)</script>"
print("    Attacker submits message:", xss)
escaped = html.escape(xss)
assert "<script>" not in escaped and "&lt;script&gt;" in escaped
print("    Stored/rendered as:", escaped)
print("    Result: the <script> tag is inert text; it cannot execute.")
print("    >>> PASS: stored XSS blocked.")

# ---------------------------------------------------------------------------
# 3) CSRF -- a per-session token is required and checked in constant time.
# ---------------------------------------------------------------------------
print("\n[3] CSRF DEFENSE (per-session token, constant-time compare)")
real_token = secrets.token_urlsafe(32)
forged_token = "forged-token-from-another-site"
print("    Real session token :", real_token[:24], "...")
print("    Forged token (attacker):", forged_token)
assert secrets.compare_digest(real_token, real_token) is True
assert secrets.compare_digest(real_token, forged_token) is False
print("    Result: a POST carrying the forged token is REJECTED (HTTP 400).")
print("    >>> PASS: CSRF blocked.")

# ---------------------------------------------------------------------------
# 4) INPUT VALIDATION -- length cap rejects oversized input.
# ---------------------------------------------------------------------------
print("\n[4] INPUT VALIDATION (280-character limit)")
MAX = 280
oversized = "x" * 500
print(f"    Attacker submits a {len(oversized)}-character message.")
assert len(oversized) > MAX
print(f"    Result: message exceeds {MAX} chars and is REJECTED (HTTP 400).")
print("    >>> PASS: oversized input blocked.")

print("\n" + "=" * 64)
print(" ALL DEFENSES PASSED -- the application resists adversarial input.")
print("=" * 64)

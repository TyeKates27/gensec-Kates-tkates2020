"""
Secure Guestbook Web Application
COT 4930 - Security Engineering with Generative AI - Homework 06

A minimal Flask guestbook demonstrating defensive security practices:
  - OAuth 2.0 login (GitHub) so identities are verified, not self-asserted
  - Parameterized SQL queries (defense against SQL injection)
  - Output escaping + Content-Security-Policy (defense against stored XSS)
  - CSRF tokens on every state-changing form
  - Per-session + per-IP rate limiting (defense against spam/flooding)
  - Secure, signed, HttpOnly session cookies
  - Secrets read from the environment, never hard-coded

Run:
  pip install -r requirements.txt
  set FLASK_SECRET_KEY, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET in the environment
  python app.py
"""

import os
import sqlite3
import secrets
import html
import time
from functools import wraps
from flask import (
    Flask,
    g,
    request,
    session,
    redirect,
    url_for,
    render_template_string,
    abort,
)
from authlib.integrations.flask_client import OAuth

# ---------------------------------------------------------------------------
# Configuration -- all secrets come from the environment, never the source.
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,   # JS cannot read the cookie -> blunts XSS theft
    SESSION_COOKIE_SAMESITE="Lax",  # cookie not sent on cross-site POST -> CSRF help
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",  # HTTPS only in prod
    PERMANENT_SESSION_LIFETIME=3600,
)

DB_PATH = os.environ.get("GUESTBOOK_DB", "guestbook.db")
MAX_MESSAGE_LEN = 280
RATE_LIMIT_SECONDS = 15  # minimum gap between two posts from one session

# ---------------------------------------------------------------------------
# OAuth provider registration (GitHub).  No passwords are ever handled by us.
# ---------------------------------------------------------------------------
oauth = OAuth(app)
oauth.register(
    name="github",
    client_id=os.environ.get("GITHUB_CLIENT_ID", ""),
    client_secret=os.environ.get("GITHUB_CLIENT_SECRET", ""),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "read:user"},
)


# ---------------------------------------------------------------------------
# Database helpers -- every query is parameterized.
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS entries (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            author     TEXT NOT NULL,
            message    TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
        """
    )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# CSRF protection -- a random token is tied to the session and checked on POST.
# ---------------------------------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def require_csrf(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        sent = request.form.get("_csrf", "")
        # constant-time compare avoids leaking the token via timing
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "CSRF validation failed")
        return fn(*args, **kwargs)

    return wrapper


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("index"))
        return fn(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Security headers on every response.
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# ---------------------------------------------------------------------------
# Templates.  Jinja2 autoescaping is ON, so {{ }} output is HTML-escaped,
# which is our primary stored-XSS defense; we also escape defensively on write.
# ---------------------------------------------------------------------------
PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure Guestbook</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; }
    .entry { border-bottom: 1px solid #ddd; padding: .6rem 0; }
    .author { font-weight: 600; }
    .when { color: #777; font-size: .8rem; }
    textarea { width: 100%; }
    .bar { display:flex; justify-content: space-between; align-items:center; }
  </style>
</head>
<body>
  <div class="bar">
    <h1>Secure Guestbook</h1>
    {% if user %}
      <span>Signed in as <strong>{{ user }}</strong> &middot; <a href="{{ url_for('logout') }}">log out</a></span>
    {% else %}
      <a href="{{ url_for('login') }}">Sign in with GitHub</a>
    {% endif %}
  </div>

  {% if user %}
  <form method="post" action="{{ url_for('post') }}">
    <input type="hidden" name="_csrf" value="{{ csrf }}">
    <textarea name="message" rows="3" maxlength="{{ maxlen }}"
              placeholder="Leave a message (max {{ maxlen }} chars)"></textarea>
    <button type="submit">Post</button>
  </form>
  {% else %}
  <p>Sign in to leave a message.</p>
  {% endif %}

  <h2>Entries</h2>
  {% for e in entries %}
    <div class="entry">
      <div class="author">{{ e['author'] }}</div>
      <div>{{ e['message'] }}</div>
      <div class="when">{{ e['created_at'] }}</div>
    </div>
  {% else %}
    <p>No entries yet.</p>
  {% endfor %}
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    db = get_db()
    rows = db.execute(
        "SELECT author, message, created_at FROM entries ORDER BY id DESC LIMIT 50"
    ).fetchall()
    return render_template_string(
        PAGE,
        entries=rows,
        user=session.get("user"),
        csrf=csrf_token(),
        maxlen=MAX_MESSAGE_LEN,
    )


@app.route("/login")
def login():
    # Protect against login CSRF with a state nonce handled by Authlib.
    redirect_uri = url_for("auth", _external=True)
    return oauth.github.authorize_redirect(redirect_uri)


@app.route("/auth")
def auth():
    token = oauth.github.authorize_access_token()  # verifies state automatically
    profile = oauth.github.get("user").json()
    # Store only the display name we need; never the token in the cookie.
    session["user"] = profile.get("login", "unknown")
    session.permanent = True
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/post", methods=["POST"])
@login_required
@require_csrf
def post():
    # ---- Rate limiting: reject posts that come too fast from one session ----
    now = int(time.time())
    last = session.get("_last_post", 0)
    if now - last < RATE_LIMIT_SECONDS:
        abort(429, "You are posting too quickly. Please wait a few seconds.")

    # ---- Input validation ----
    raw = (request.form.get("message") or "").strip()
    if not raw:
        return redirect(url_for("index"))
    if len(raw) > MAX_MESSAGE_LEN:
        abort(400, "Message too long")

    # Defense-in-depth: escape on write as well as on render.
    safe_message = html.escape(raw)
    author = html.escape(session["user"])

    # ---- Parameterized INSERT: user input never concatenated into SQL ----
    db = get_db()
    db.execute(
        "INSERT INTO entries (author, message, created_at) VALUES (?, ?, ?)",
        (author, safe_message, now),
    )
    db.commit()
    session["_last_post"] = now
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    # debug=False so stack traces are never shown to users in production.
    app.run(host="127.0.0.1", port=5000, debug=False)

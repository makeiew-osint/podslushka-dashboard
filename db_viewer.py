from __future__ import annotations

import csv
import html
import hashlib
import hmac
import io
import json
import logging
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import base64
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from contextlib import contextmanager
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # PostgreSQL is optional for local SQLite development.
    psycopg = None
    dict_row = None


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "podslushka.db"
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
HOST = os.getenv("HOST", "0.0.0.0" if os.getenv("PORT") else "127.0.0.1")
PORT = int(os.getenv("PORT", "8765"))
SESSIONS: dict[str, str] = {}  # legacy in-process cache; DB sessions are authoritative
OAUTH_STATES: dict[str, tuple[str, int]] = {}
OWNER_USERNAME = os.getenv("OWNER_USERNAME", "")
OWNER_PASSWORD = os.getenv("OWNER_PASSWORD", "")
OWNER_2FA_SECRET = os.getenv("OWNER_2FA_SECRET", "").strip()
OWNER_2FA_REQUIRED = os.getenv("OWNER_2FA_REQUIRED", "").strip().lower() in {"1", "true", "yes"}
SYNC_SECRET = os.getenv("DASHBOARD_SYNC_SECRET", "")
TELEGRAM_BOT_USERNAME = os.getenv("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@")
TELEGRAM_BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
OAUTH_BASE_URL = os.getenv("OAUTH_BASE_URL", "").strip().rstrip("/")
OAUTH_SIGNING_SECRET = (
    os.getenv("OAUTH_SIGNING_SECRET", "").strip()
    or SYNC_SECRET
    or OWNER_PASSWORD
    or GOOGLE_CLIENT_SECRET
    or TELEGRAM_BOT_TOKEN
)
SESSION_TTL = 60 * 60 * 12
LOGIN_WINDOW = 15 * 60
LOGIN_MAX_ATTEMPTS = 8
ROLE_PERMISSIONS = {
    "owner": {"overview", "users", "posts", "user-search", "access", "owners", "actions", "export"},
    "admin": {"overview", "users", "posts", "user-search", "actions", "export"},
    "moderator": {"overview", "users", "posts", "user-search", "export"},
    "read-only": {"overview", "users", "posts", "user-search", "export"},
    "user": {"overview", "users", "posts", "user-search"},
}
BOT_STATUS = {"state": "disabled", "error": ""}
BOT_PROCESS = None
BOT_RESTART_LOCK = threading.Lock()


def adapt_sql(query: str) -> str:
    if DATABASE_URL:
        return query.replace("?", "%s").replace(
            "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY"
        )
    return query


class DatabaseConnection:
    def __init__(self, connection):
        self._connection = connection

    def execute(self, query, params=()):
        return self._connection.execute(adapt_sql(query), params)

    def __getattr__(self, name):
        return getattr(self._connection, name)


@contextmanager
def db_connect(readonly: bool = False):
    if DATABASE_URL:
        if psycopg is None:
            raise RuntimeError("psycopg is required when DATABASE_URL is set")
        connection = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    else:
        uri = f"file:{DB_PATH}?mode=ro" if readonly else str(DB_PATH)
        connection = sqlite3.connect(uri, uri=readonly)
        connection.row_factory = sqlite3.Row
    wrapped = DatabaseConnection(connection)
    try:
        yield wrapped
    except Exception:
        connection.rollback()
        raise
    else:
        connection.commit()
    finally:
        connection.close()


DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError,) + (
    (psycopg.errors.UniqueViolation,) if psycopg is not None else ()
)
DB_ERRORS = (sqlite3.Error,) + ((psycopg.Error,) if psycopg is not None else ())


def start_embedded_bot() -> None:
    global BOT_PROCESS
    if os.getenv("RUN_BOT_IN_WEB", "").lower() not in {"1", "true", "yes"}:
        return
    def supervise() -> None:
        global BOT_PROCESS
        while True:
            with BOT_RESTART_LOCK:
                BOT_STATUS["state"] = "starting"
                try:
                    BOT_PROCESS = subprocess.Popen(
                        [sys.executable, "-u", str(ROOT / "bot.py")],
                        cwd=str(ROOT),
                        env=os.environ.copy(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        bufsize=1,
                    )
                    BOT_STATUS["state"] = "running"
                except OSError as exc:
                    BOT_STATUS["state"] = "error"
                    BOT_STATUS["error"] = str(exc)[-500:]
                    logging.exception("Embedded Telegram bot failed to start")
                    time.sleep(10)
                    continue
            assert BOT_PROCESS.stdout is not None
            for line in BOT_PROCESS.stdout:
                message = line.strip()
                if message:
                    BOT_STATUS["error"] = message[-500:]
                    logging.info("Telegram bot: %s", message)
            exit_code = BOT_PROCESS.wait()
            BOT_STATUS["state"] = "error"
            BOT_STATUS["error"] = f"Бот остановился (код {exit_code}). Последняя строка: {BOT_STATUS['error']}"
            time.sleep(5)

    threading.Thread(target=supervise, name="telegram-bot-supervisor", daemon=True).start()


def esc(value) -> str:
    return html.escape("—" if value is None else str(value))


def db_rows(query: str, params=()):
    with db_connect(readonly=True) as conn:
        return conn.execute(query, params).fetchall()


def scalar(query: str):
    rows = db_rows(query)
    if not rows:
        return 0
    row = rows[0]
    return next(iter(row.values())) if isinstance(row, dict) else row[0]


def row_value(row, key: str, index: int = 0):
    return row[key] if isinstance(row, dict) else row[index]


def table_columns(table: str) -> set[str]:
    """Return columns without assuming the bot and dashboard schemas are identical."""
    if DATABASE_URL:
        rows = db_rows(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name=?", (table,)
        )
        return {row["column_name"] for row in rows}
    return {row[1] for row in db_rows(f"PRAGMA table_info({table})")}


def optional_rows(query: str, params=()):
    try:
        return db_rows(query, params)
    except DB_ERRORS:
        return []


def dashboard_role(username: str | None) -> str:
    if not username:
        return ""
    if OWNER_USERNAME and username == OWNER_USERNAME:
        return "owner"
    try:
        with db_connect(readonly=True) as conn:
            row = conn.execute(
                "SELECT role, status FROM dashboard_users WHERE username=?", (username,)
            ).fetchone()
        if row and row_value(row, "status", 1) == "approved":
            role = str(row_value(row, "role", 0) or "read-only").lower()
            return {"readonly": "read-only", "read_only": "read-only", "user": "read-only"}.get(role, role)
    except DB_ERRORS:
        return ""
    return ""


def can_access(username: str | None, section: str) -> bool:
    return section in ROLE_PERMISSIONS.get(dashboard_role(username), set())


def oauth_state(provider: str) -> str:
    nonce = secrets.token_urlsafe(24)
    issued = int(time.time())
    payload = f"{provider}:{nonce}:{issued}"
    signature = hmac_digest(payload, OAUTH_SIGNING_SECRET)
    OAUTH_STATES[nonce] = (provider, issued)
    return f"{nonce}.{signature}"


def hmac_digest(value: str, secret: str) -> str:
    return hmac.new(
        (secret or "dashboard-state").encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def consume_oauth_state(value: str, provider: str) -> bool:
    try:
        nonce, signature = value.split(".", 1)
        expected_provider, issued = OAUTH_STATES.pop(nonce)
    except (ValueError, KeyError):
        return False
    if expected_provider != provider or int(time.time()) - issued > 600:
        return False
    expected = hmac_digest(f"{provider}:{nonce}:{issued}", OAUTH_SIGNING_SECRET)
    return secrets.compare_digest(signature, expected)


def oauth_redirect(provider: str) -> str:
    return f"{OAUTH_BASE_URL}/auth/{provider}/callback"


def telegram_login_valid(query: dict[str, list[str]]) -> bool:
    supplied = query.get("hash", [""])[0]
    if not supplied or not TELEGRAM_BOT_USERNAME or not TELEGRAM_BOT_TOKEN:
        return False
    fields = [f"{key}={query[key][0]}" for key in sorted(query) if key != "hash"]
    secret = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode("utf-8")).digest()
    expected = hmac.new(secret, "\n".join(fields).encode("utf-8"), hashlib.sha256).hexdigest()
    try:
        auth_date = int(query.get("auth_date", ["0"])[0] or 0)
    except (TypeError, ValueError):
        return False
    return auth_date > int(time.time()) - 86400 and secrets.compare_digest(supplied, expected)


def init_auth() -> None:
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                role TEXT NOT NULL DEFAULT 'user',
                created_at INTEGER NOT NULL
            )
        """)
        if DATABASE_URL:
            columns = {
                row["column_name"]
                for row in conn.execute(
                    """SELECT column_name FROM information_schema.columns
                       WHERE table_schema='public' AND table_name='dashboard_users'"""
                )
            }
        else:
            columns = {row[1] for row in conn.execute("PRAGMA table_info(dashboard_users)")}
        if "status" not in columns:
            conn.execute("ALTER TABLE dashboard_users ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
        if "role" not in columns:
            conn.execute("ALTER TABLE dashboard_users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        for name, definition in {
            "oauth_provider": "TEXT",
            "oauth_subject": "TEXT",
            "email": "TEXT",
            "display_name": "TEXT",
            "totp_secret": "TEXT",
        }.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE dashboard_users ADD COLUMN {name} {definition}")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_oauth "
            "ON dashboard_users(oauth_provider, oauth_subject)"
        )
        conn.execute("""CREATE TABLE IF NOT EXISTS dashboard_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            created_at INTEGER NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS dashboard_sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            ip TEXT,
            user_agent TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
            key TEXT PRIMARY KEY,
            attempts INTEGER NOT NULL DEFAULT 0,
            window_started INTEGER NOT NULL
        )""")
        conn.execute("CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY, first_name TEXT, last_name TEXT, username TEXT, language_code TEXT, is_premium INTEGER DEFAULT 0, ui_lang TEXT, first_seen INTEGER, last_seen INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, kind TEXT, text TEXT, status TEXT DEFAULT 'pending', created_at INTEGER, public_id INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS bans (user_id INTEGER PRIMARY KEY, reason TEXT, created_at INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER, reason TEXT, created_at INTEGER)")
        # These tables are also created by db.py. IF NOT EXISTS keeps PostgreSQL authoritative
        # and never replaces or truncates the bot schema when the dashboard starts.
        conn.execute("CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, public_id INTEGER, user_id INTEGER, text TEXT, created_at INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS votes (id INTEGER PRIMARY KEY AUTOINCREMENT, public_id INTEGER, user_id INTEGER, vote INTEGER, created_at INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS warns (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, reason TEXT, post_id INTEGER, admin_id INTEGER, created_at INTEGER)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_actions_created ON dashboard_actions(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_expiry ON dashboard_sessions(expires_at)")
        conn.commit()


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
    except (AttributeError, ValueError):
        return False
    expected = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 200_000
    ).hex()
    return secrets.compare_digest(expected, digest_hex)


def auth_user(handler: BaseHTTPRequestHandler) -> str | None:
    cookie = handler.headers.get("Cookie", "")
    token = next((item.split("=", 1)[1] for item in cookie.split("; ")
                  if item.startswith("session=")), None)
    if not token:
        return None
    cached = SESSIONS.get(token)
    now = int(time.time())
    try:
        with db_connect() as conn:
            conn.execute("DELETE FROM dashboard_sessions WHERE expires_at <= ?", (now,))
            row = conn.execute(
                """SELECT s.username FROM dashboard_sessions s
                   LEFT JOIN dashboard_users u ON u.username=s.username
                   WHERE s.token=? AND s.expires_at>?
                     AND (u.status='approved' OR s.username=?)""",
                (token, now, OWNER_USERNAME),
            ).fetchone()
            if row:
                username = row_value(row, "username", 0)
                SESSIONS[token] = username
                return username
    except DB_ERRORS:
        return cached
    SESSIONS.pop(token, None)
    return None


def is_owner(username: str | None) -> bool:
    if not username:
        return False
    if OWNER_USERNAME and username == OWNER_USERNAME:
        return True
    with db_connect(readonly=True) as conn:
        row = conn.execute(
            "SELECT role, status FROM dashboard_users WHERE username=?", (username,)
        ).fetchone()
    return bool(
        row
        and row_value(row, "role", 0) == "owner"
        and row_value(row, "status", 1) == "approved"
    )


def log_action(actor: str, action: str, target: str = "") -> None:
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO dashboard_actions (actor, action, target, created_at) VALUES (?, ?, ?, ?)",
            (actor, action, target, int(datetime.now().timestamp())),
        )
        conn.commit()


def create_session(username: str, handler: BaseHTTPRequestHandler) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO dashboard_sessions
               (token, username, created_at, expires_at, ip, user_agent)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                token, username, now, now + SESSION_TTL,
                handler.client_address[0] if handler.client_address else "",
                handler.headers.get("User-Agent", "")[:500],
            ),
        )
        conn.commit()
    SESSIONS[token] = username
    return token


def destroy_session(handler: BaseHTTPRequestHandler) -> str | None:
    cookie = handler.headers.get("Cookie", "")
    token = next((item.split("=", 1)[1] for item in cookie.split("; ")
                  if item.startswith("session=")), None)
    if token:
        with db_connect() as conn:
            conn.execute("DELETE FROM dashboard_sessions WHERE token=?", (token,))
            conn.commit()
        SESSIONS.pop(token, None)
    return token


def rate_limit_key(handler: BaseHTTPRequestHandler, username: str) -> str:
    ip = handler.client_address[0] if handler.client_address else "unknown"
    return f"{ip}:{username.lower()[:160]}"


def login_allowed(handler: BaseHTTPRequestHandler, username: str) -> bool:
    key = rate_limit_key(handler, username)
    now = int(time.time())
    with db_connect() as conn:
        row = conn.execute("SELECT attempts, window_started FROM login_attempts WHERE key=?", (key,)).fetchone()
        if not row:
            return True
        attempts = int(row_value(row, "attempts", 0) or 0)
        started = int(row_value(row, "window_started", 1) or now)
        return now - started >= LOGIN_WINDOW or attempts < LOGIN_MAX_ATTEMPTS


def record_login_attempt(handler: BaseHTTPRequestHandler, username: str, success: bool) -> None:
    key = rate_limit_key(handler, username)
    now = int(time.time())
    with db_connect() as conn:
        row = conn.execute("SELECT attempts, window_started FROM login_attempts WHERE key=?", (key,)).fetchone()
        if success or not row or now - int(row_value(row, "window_started", 1) or now) >= LOGIN_WINDOW:
            conn.execute(
                """INSERT INTO login_attempts(key, attempts, window_started) VALUES (?, ?, ?)
                   ON CONFLICT(key) DO UPDATE SET attempts=excluded.attempts, window_started=excluded.window_started""",
                (key, 0 if success else 1, now),
            )
        else:
            conn.execute("UPDATE login_attempts SET attempts=attempts+1 WHERE key=?", (key,))
        conn.commit()


def totp_valid(secret: str, supplied: str) -> bool:
    if not secret:
        return True
    supplied = "".join(ch for ch in (supplied or "") if ch.isdigit())
    if len(supplied) != 6:
        return False
    try:
        encoded = secret.replace(" ", "").upper()
        key = base64.b32decode(encoded + "=" * (-len(encoded) % 8), casefold=True)
    except (ValueError, base64.binascii.Error):
        return False
    counter = int(time.time()) // 30
    for offset in (-1, 0, 1):
        msg = (counter + offset).to_bytes(8, "big")
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        index = digest[-1] & 15
        code = (int.from_bytes(digest[index:index + 4], "big") & 0x7fffffff) % 1000000
        if secrets.compare_digest(f"{code:06d}", supplied):
            return True
    return False


def oauth_account(provider: str, subject: str, email: str = "", display_name: str = "") -> tuple[str, str]:
    """Find or create a pending dashboard account for a verified OAuth identity."""
    subject = str(subject or "").strip()
    if not subject:
        raise ValueError("OAuth provider returned no stable subject")
    with db_connect() as conn:
        row = conn.execute(
            """SELECT username, status FROM dashboard_users
               WHERE oauth_provider=? AND oauth_subject=?""",
            (provider, subject),
        ).fetchone()
        if row:
            username = row_value(row, "username", 0)
            status = row_value(row, "status", 1)
            conn.execute(
                "UPDATE dashboard_users SET email=COALESCE(?, email), display_name=COALESCE(?, display_name) WHERE username=?",
                (email or None, display_name or None, username),
            )
            conn.commit()
            return username, status
        username = f"{provider}_{hashlib.sha256(subject.encode('utf-8')).hexdigest()[:24]}"
        conn.execute(
            """INSERT INTO dashboard_users
               (username, password_hash, status, role, oauth_provider, oauth_subject,
                email, display_name, created_at)
               VALUES (?, ?, 'pending', 'user', ?, ?, ?, ?, ?)""",
            (
                username, password_hash(secrets.token_urlsafe(32)), provider, subject,
                email or None, display_name or None, int(time.time()),
            ),
        )
        conn.commit()
    return username, "pending"


def complete_oauth(handler: BaseHTTPRequestHandler, provider: str, subject: str,
                   email: str = "", display_name: str = "") -> None:
    username, status = oauth_account(provider, subject, email, display_name)
    if status != "approved":
        log_action(f"{provider}:{subject[:80]}", "OAuth account pending approval", username)
        handler.send_html(auth_page(
            f"Личность подтверждена ({esc(email or display_name or provider)}), "
            "но доступ ещё не одобрен владельцем."
        ))
        return
    token = create_session(username, handler)
    log_action(username, f"OAuth {provider} login success", username)
    handler.send_response(302)
    handler.send_header("Location", "/")
    secure = "; Secure" if OAUTH_BASE_URL.startswith("https://") else ""
    handler.send_header("Set-Cookie", f"session={token}; HttpOnly; SameSite=Strict{secure}")
    handler.end_headers()


def auth_page(message: str = "") -> str:
    google_link = (f'<a class="button oauth-button google-button" href="/auth/google"><span class="oauth-icon google-icon">G</span><span>Продолжить с Google</span></a>'
                   if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and OAUTH_BASE_URL else
                   '<span class="oauth-disabled">Google OAuth disabled: set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and OAUTH_BASE_URL.</span>')
    telegram_link = (f'<div class="telegram-button"><span class="oauth-icon telegram-icon">➤</span><span class="telegram-label">Продолжить с Telegram</span><script async src="https://telegram.org/js/telegram-widget.js?22" data-telegram-login="{esc(TELEGRAM_BOT_USERNAME)}" data-size="large" data-auth-url="{esc(oauth_redirect("telegram"))}" data-request-access="write"></script></div>'
                     if TELEGRAM_BOT_USERNAME and TELEGRAM_BOT_TOKEN and OAUTH_BASE_URL else
                     '<span class="oauth-disabled">Telegram Login disabled: set TELEGRAM_BOT_USERNAME, BOT_TOKEN and OAUTH_BASE_URL.</span>')
    oauth_links = f'<div class="oauth"><div class="oauth-title">Безопасный вход</div>{google_link}{telegram_link}<p class="hint">Новая учётная запись сначала ожидает одобрения владельца.</p></div>'
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Вход · Podslushka</title><style>
:root{{--bg:#090b1c;--panel:#171936;--line:#353866;--text:#f5f4ff;--muted:#a5a8c7;--blue:#7b61ff;--blue2:#27d3c2;--pink:#e15bff}}
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;
background:radial-gradient(circle at 8% 8%,#6248d855 0,transparent 28%),radial-gradient(circle at 92% 88%,#16c8bd33 0,transparent 30%),linear-gradient(135deg,#090b1c,#11142c 55%,#0a1b2a);
color:var(--text);font:15px Inter,Segoe UI,Arial,sans-serif;perspective:1400px}}
.shell{{width:min(920px,100%);display:grid;grid-template-columns:1fr 1fr;overflow:hidden;border:1px solid #2a4265;
border-radius:24px;background:linear-gradient(145deg,#1c2045dd,#10152ddd);box-shadow:28px 34px 0 #050611aa,0 24px 80px #000b,0 0 0 1px #8d7cff44;backdrop-filter:blur(18px);transform:rotateX(2deg) rotateY(-2deg);transform-style:preserve-3d}}
.intro{{padding:48px 42px;background:linear-gradient(145deg,#29235f,#131a3a);position:relative;overflow:hidden;transform:translateZ(18px)}}
.intro:before{{content:"";position:absolute;pointer-events:none;width:180px;height:180px;border-radius:50%;right:35px;top:35px;background:radial-gradient(circle at 30% 25%,#fff8,#7b61ff66 18%,#21175c 65%);box-shadow:inset -20px -24px 25px #08061d99,0 20px 40px #0007;transform:translateZ(35px);opacity:.8}}
.intro:after{{content:"";position:absolute;pointer-events:none;width:260px;height:260px;border-radius:50%;right:-100px;bottom:-120px;background:#27d3c222;box-shadow:0 0 70px #27d3c233}}
.brand{{display:flex;align-items:center;gap:12px;font-weight:800;font-size:22px;letter-spacing:-.5px}}
.logo{{width:44px;height:44px;display:grid;place-items:center;border-radius:13px;background:linear-gradient(135deg,#a98bff,#6450ed);font-size:23px;box-shadow:7px 8px 0 #34268d,0 12px 24px #7b61ff88;transform:translateZ(30px)}}
.intro h1{{font-size:35px;line-height:1.08;margin:58px 0 16px;letter-spacing:-1.5px}}
.intro p{{color:#b7c8de;line-height:1.65;max-width:320px}}.features{{margin-top:34px;display:grid;gap:13px;color:#d7e6fa}}
.feature{{display:flex;gap:10px;align-items:center}}.check{{color:#83b2ff;font-size:18px}}
.auth{{padding:42px 40px;background:#111c2e;transform:translateZ(10px);box-shadow:inset 1px 0 #ffffff0d}}.auth h2{{margin:0 0 8px;font-size:25px}}
.sub{{color:var(--muted);margin:0 0 26px}}.error{{min-height:22px;margin:0 0 9px;color:#ff9eaa;font-size:13px}}
.tabs{{display:grid;grid-template-columns:1fr 1fr;gap:5px;padding:4px;margin-bottom:22px;background:#0b1423;border-radius:10px}}
.tab{{border:0;background:transparent;color:var(--muted);padding:10px;border-radius:7px;font-weight:700;cursor:pointer;transition:.18s;box-shadow:0 3px 0 #080a1b}}
.tab.active{{background:#263e63;color:#fff;transform:translateY(-1px);box-shadow:0 4px 0 #101b31}}.tab:active,.toggle:active{{transform:translateY(2px);box-shadow:0 1px 0 #080f1e}}.form{{display:none}}.form.active{{display:block}}
.field{{display:block;margin:15px 0 6px;color:#a9bbd3;font-size:13px;font-weight:600}}
.input-wrap{{position:relative}}input{{width:100%;padding:13px 43px 13px 14px;border-radius:10px;border:1px solid var(--line);
background:#0c1729;color:#fff;outline:none;font-size:15px;transition:.2s}}input:focus{{border-color:var(--blue2);box-shadow:0 0 0 3px #27d3c233,0 6px 0 #176d78;transform:translateY(-2px)}}
.toggle{{position:absolute;right:10px;top:9px;border:0;background:#1b2b46;color:#9fb8d8;cursor:pointer;font-size:17px;border-radius:7px;padding:4px 7px;box-shadow:0 3px 0 #080f1e;transition:.18s}}
.submit{{width:100%;margin-top:22px;padding:13px;border:0;border-radius:10px;background:linear-gradient(135deg,var(--blue),#3e6fe8);
color:white;font-weight:800;font-size:15px;cursor:pointer;background:linear-gradient(135deg,#7b61ff,#d15bff);box-shadow:0 6px 0 #4934a5,0 12px 20px #7b61ff55;transition:.2s}}
.submit:hover{{transform:translateY(-2px);filter:brightness(1.12)}}.submit:active{{transform:translateY(3px);box-shadow:0 2px 0 #4934a5}}.submit:focus-visible,.tab:focus-visible,.toggle:focus-visible,.oauth-button:focus-visible{{outline:3px solid var(--blue2);outline-offset:3px}}.oauth{{display:grid;gap:10px;margin-top:22px;padding-top:18px;border-top:1px solid #334466}}.oauth-title{{color:#a9bbd3;font-size:12px;font-weight:700}}.oauth-button,.telegram-button{{position:relative;display:flex;align-items:center;justify-content:center;gap:10px;width:100%;min-height:48px;padding:11px 16px;border:0;border-radius:12px;text-decoration:none;color:#fff;font-size:14px;font-weight:800;cursor:pointer;transition:.2s;transform:translateZ(8px)}}.oauth-button:hover,.telegram-button:hover{{transform:translateY(-2px);filter:brightness(1.1)}}.oauth-button:active,.telegram-button:active{{transform:translateY(2px)}}.google-button{{background:linear-gradient(135deg,#4285f4,#245bd1);box-shadow:0 5px 0 #163c8e,0 10px 20px #245bd144}}.telegram-button{{overflow:hidden;background:linear-gradient(135deg,#39a9e8,#1988c9);box-shadow:0 5px 0 #0d5c88,0 10px 20px #1988c944}}.telegram-button .telegram-label{{pointer-events:none}}.telegram-button iframe{{position:absolute;inset:0;width:100%!important;height:48px!important;opacity:0;z-index:2}}.oauth-icon{{display:grid;place-items:center;width:24px;height:24px;border-radius:50%;font-size:16px;font-weight:900;flex:none}}.google-icon{{background:#fff;color:#4285f4;font-family:Arial}}.telegram-icon{{background:#fff;color:#1988c9;transform:rotate(-25deg);font-size:14px}}.oauth-disabled{{color:#f0b7bd;font-size:12px;line-height:1.4}}.hint{{margin:20px 0 0;text-align:center;color:#858ab1;font-size:12px}}
@media(max-width:700px){{.shell{{grid-template-columns:1fr;max-width:460px}}.intro{{padding:30px}}.intro h1{{margin:28px 0 12px;font-size:29px}}.features{{display:none}}.auth{{padding:30px}}}}
</style></head><body><div class="shell">
<section class="intro"><div class="brand"><span class="logo">◈</span><span>Podslushka DB</span></div>
<h1>Ваша панель<br>под контролем.</h1><p>Управляйте заявками, пользователями и модерацией в одном защищённом рабочем пространстве.</p>
<div class="features"><div class="feature"><span class="check">✓</span> Локальная защищённая база</div>
<div class="feature"><span class="check">✓</span> Быстрый поиск и фильтры</div>
<div class="feature"><span class="check">✓</span> Резервные копии в один клик</div></div></section>
<section class="auth"><h2 id="title">Добро пожаловать</h2><p class="sub" id="subtitle">Войдите, чтобы продолжить работу.</p>
<div class="error">{esc(message)}</div><div class="tabs"><button class="tab active" data-tab="login">Войти</button><button class="tab" data-tab="register">Регистрация</button></div>
<form class="form active" id="login" method="post" action="/login"><label class="field">Логин</label><input name="username" placeholder="Введите логин" required autocomplete="username">
<label class="field">Пароль</label><div class="input-wrap"><input name="password" type="password" placeholder="Введите пароль" required autocomplete="current-password"><button type="button" class="toggle">◉</button></div>
<label class="field">Код 2FA <span class="muted">(включается отдельно)</span></label><input name="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Необязательно" title="Введите 6 цифр, если 2FA включена">
<button class="submit" type="submit">Войти в панель →</button></form>
<form class="form" id="register" method="post" action="/register"><label class="field">Логин</label><input name="username" placeholder="Придумайте логин" required minlength="3" autocomplete="username">
<label class="field">Пароль</label><div class="input-wrap"><input name="password" type="password" placeholder="Минимум 8 символов" required minlength="8" autocomplete="new-password"><button type="button" class="toggle">◉</button></div><button class="submit" type="submit">Создать аккаунт →</button></form>{oauth_links}
<p class="hint">Доступ только для авторизованных пользователей · заявки подтверждает владелец</p></section></div>
<script>
document.querySelectorAll('.tab').forEach(tab => tab.addEventListener('click', () => {{
 document.querySelectorAll('.tab,.form').forEach(el => el.classList.remove('active'));
 tab.classList.add('active'); document.getElementById(tab.dataset.tab).classList.add('active');
 document.getElementById('title').textContent = tab.dataset.tab === 'login' ? 'Добро пожаловать' : 'Создайте аккаунт';
 document.getElementById('subtitle').textContent = tab.dataset.tab === 'login' ? 'Войдите, чтобы продолжить работу.' : 'Регистрация займёт меньше минуты.';
}}));
document.querySelectorAll('.toggle').forEach(btn => btn.addEventListener('click', () => {{
 const input = btn.previousElementSibling; input.type = input.type === 'password' ? 'text' : 'password';
 btn.textContent = input.type === 'password' ? '◉' : '◉';
}}));
</script></body></html>"""


def fmt_time(value, with_seconds: bool = False) -> str:
    try:
        if not value:
            return "—"
        pattern = "%d.%m.%Y %H:%M:%S" if with_seconds else "%d.%m.%Y %H:%M"
        return datetime.fromtimestamp(float(value)).strftime(pattern)
    except (TypeError, ValueError, OSError):
        return "—"


def user_detail_page(current_user: str, user_id: int) -> str:
    if not can_access(current_user, "users"):
        return ""
    user_rows = optional_rows("SELECT * FROM users WHERE user_id=?", (user_id,))
    if not user_rows:
        return ""
    user = user_rows[0]
    display_name = " ".join(filter(None, [user["first_name"], user["last_name"]]))
    posts = optional_rows(
        "SELECT id, kind, status, text, public_id, created_at FROM posts "
        "WHERE user_id=? ORDER BY created_at DESC LIMIT 500", (user_id,)
    )
    comments = optional_rows(
        "SELECT id, public_id, text, created_at FROM comments "
        "WHERE user_id=? ORDER BY created_at DESC LIMIT 500", (user_id,)
    )
    votes = optional_rows(
        "SELECT id, public_id, vote, created_at FROM votes "
        "WHERE user_id=? ORDER BY created_at DESC LIMIT 500", (user_id,)
    )
    bans = optional_rows("SELECT user_id, reason, created_at FROM bans WHERE user_id=?", (user_id,))
    warns = optional_rows(
        "SELECT id, reason, post_id, created_at FROM warns "
        "WHERE user_id=? ORDER BY created_at DESC LIMIT 500", (user_id,)
    )
    reports = optional_rows(
        "SELECT id, reason, created_at FROM reports "
        "WHERE reporter_id=? ORDER BY created_at DESC LIMIT 500", (user_id,)
    )
    posts_html = "".join(
        f"<tr><td>#{esc(row['id'])}</td><td>{esc(row['kind'])}</td>"
        f"<td>{esc(row['status'])}</td><td>{esc((row['text'] or '')[:240])}</td>"
        f"<td>{esc(fmt_time(row['created_at']))}</td></tr>" for row in posts
    ) or '<tr><td colspan="5">Нет заявок</td></tr>'
    comments_html = "".join(
        f"<tr><td>#{esc(row['id'])}</td><td>{esc(row['public_id'])}</td>"
        f"<td>{esc(row['text'])}</td><td>{esc(fmt_time(row['created_at']))}</td></tr>"
        for row in comments
    ) or '<tr><td colspan="4">Нет комментариев</td></tr>'
    votes_html = "".join(
        f"<tr><td>#{esc(row['id'])}</td><td>{esc(row['public_id'])}</td>"
        f"<td>{esc(row['vote'])}</td><td>{esc(fmt_time(row['created_at']))}</td></tr>"
        for row in votes
    ) or '<tr><td colspan="4">Нет голосов</td></tr>'
    reports_html = "".join(
        f"<tr><td>#{esc(row['id'])}</td><td>{esc(row['reason'])}</td>"
        f"<td>{esc(fmt_time(row['created_at']))}</td></tr>" for row in reports
    ) or '<tr><td colspan="3">Нет жалоб</td></tr>'
    bans_html = "".join(
        f"<tr><td>{esc(row['user_id'])}</td><td>{esc(row['reason'])}</td>"
        f"<td>{esc(fmt_time(row['created_at']))}</td></tr>" for row in bans
    ) or '<tr><td colspan="3">Нет банов</td></tr>'
    warns_html = "".join(
        f"<tr><td>#{esc(row['id'])}</td><td>{esc(row['reason'])}</td>"
        f"<td>{esc(row['post_id'])}</td><td>{esc(fmt_time(row['created_at']))}</td></tr>"
        for row in warns
    ) or '<tr><td colspan="4">Нет предупреждений</td></tr>'
    role = dashboard_role(current_user)
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Пользователь {esc(user_id)} · Podslushka</title><style>
body{{margin:0;background:#090b1c;color:#f5f4ff;font:14px Segoe UI,Arial,sans-serif;padding:28px}}
main{{max-width:1200px;margin:auto}}a,button{{display:inline-block;color:#fff;text-decoration:none;
border:0;border-radius:10px;padding:10px 15px;font-weight:700;background:linear-gradient(135deg,#7b61ff,#3e6fe8);
box-shadow:0 5px 0 #34268d;cursor:pointer;transition:.18s}}a:hover,button:hover{{transform:translateY(-2px);
filter:brightness(1.1)}}a:focus-visible,button:focus-visible{{outline:3px solid #27d3c2;outline-offset:3px}}
section{{margin-top:22px;background:#171936;border:1px solid #353866;border-radius:14px;padding:18px;
box-shadow:7px 8px 0 #050611}}h1{{margin:18px 0 4px}}h2{{margin:0 0 12px}}table{{border-collapse:collapse;
width:100%;min-width:650px}}.table{{overflow:auto}}th,td{{padding:10px;border-bottom:1px solid #353866;
text-align:left}}th{{color:#8fc0ff}}.muted{{color:#a5a8c7}}.badge{{display:inline-block;padding:5px 9px;
border-radius:99px;background:#304664;color:#d7e8ff}}</style></head><body><main>
<a href="/?view=users">← К пользователям</a><h1>{esc(display_name or "Пользователь")}
<span class="badge">{esc(role)}</span></h1><p class="muted">Telegram ID: <code>{esc(user_id)}</code>
 · @{esc(user["username"]) if user["username"] else "—"} · Язык: {esc(user["ui_lang"] or user["language_code"])}</p>
<section><h2>Профиль</h2><p>Premium: {"да" if user["is_premium"] else "нет"} · Первый контакт:
{esc(fmt_time(user["first_seen"]))} · Последний контакт: {esc(fmt_time(user["last_seen"]))}</p></section>
<section><h2>Заявки ({len(posts)})</h2><div class="table"><table><tr><th>ID</th><th>Тип</th>
<th>Статус</th><th>Текст</th><th>Дата</th></tr>{posts_html}</table></div></section>
<section><h2>Жалобы ({len(reports)})</h2><div class="table"><table><tr><th>ID</th><th>Причина</th>
<th>Дата</th></tr>{reports_html}</table></div></section>
<section><h2>Комментарии ({len(comments)})</h2><div class="table"><table><tr><th>ID</th>
<th>Публикация</th><th>Текст</th><th>Дата</th></tr>{comments_html}</table></div></section>
<section><h2>Голоса ({len(votes)})</h2><div class="table"><table><tr><th>ID</th><th>Публикация</th>
<th>Голос</th><th>Дата</th></tr>{votes_html}</table></div></section>
<section><h2>Баны ({len(bans)}) и предупреждения ({len(warns)})</h2><div class="table">
<table><tr><th>User ID</th><th>Причина</th><th>Дата</th></tr>{bans_html}</table><br>
<table><tr><th>ID</th><th>Причина</th><th>Пост</th><th>Дата</th></tr>{warns_html}</table>
</div></section></main></body></html>"""


def page(current_user: str = "", section: str = "overview") -> str:
    role = dashboard_role(current_user)
    owner = role == "owner"
    if not can_access(current_user, section):
        section = "overview"
    stats = {
        "users": scalar("SELECT COUNT(*) FROM users"),
        "posts": scalar("SELECT COUNT(*) FROM posts"),
        "pending": scalar("SELECT COUNT(*) FROM posts WHERE status='pending'"),
        "published": scalar("SELECT COUNT(*) FROM posts WHERE status='published'"),
        "banned": scalar("SELECT COUNT(*) FROM bans"),
        "reports": scalar("SELECT COUNT(*) FROM reports"),
    }
    users = db_rows("""
        SELECT u.*, COUNT(p.id) AS posts_count
        FROM users u LEFT JOIN posts p ON p.user_id = u.user_id
        GROUP BY u.user_id ORDER BY u.last_seen DESC LIMIT 500
    """)
    posts = db_rows("""
        SELECT p.id, p.user_id, p.kind, p.status, p.public_id, p.text, p.created_at,
               u.username, u.first_name
        FROM posts p LEFT JOIN users u ON u.user_id = p.user_id
        ORDER BY p.created_at DESC LIMIT 100
    """)

    cards = "".join(
        f'<div class="card"><b>{label}</b><strong>{value}</strong></div>'
        for label, value in (
            ("Пользователи", stats["users"]), ("Заявки", stats["posts"]),
            ("На модерации", stats["pending"]), ("Опубликовано", stats["published"]),
            ("Баны", stats["banned"]), ("Жалобы", stats["reports"]),
        )
    )
    user_rows = "".join(
        "<tr class=\"user-row\">"
        f"<td><a class=\"button-link\" href=\"/user?id={esc(row['user_id'])}\"><code>{esc(row['user_id'])}</code></a></td>"
        f"<td>{esc(row['first_name'])} {esc(row['last_name'])}</td>"
        f"<td>{('@' + row['username']) if row['username'] else '—'}</td>"
        f"<td>{esc(row['ui_lang'] or row['language_code'])}</td>"
        f"<td>{esc(row['posts_count'])}</td>"
        f"<td>{datetime.fromtimestamp(row['last_seen']).strftime('%d.%m.%Y %H:%M') if row['last_seen'] else '—'}</td>"
        "</tr>"
        for row in users
    )
    post_rows = "".join(
        f"<tr class=\"post-row\" data-status=\"{esc(row['status'])}\">"
        f"<td>#{esc(row['id'])}</td><td><code>{esc(row['user_id'])}</code></td>"
        f"<td>{esc(row['first_name'])} {('@' + row['username']) if row['username'] else ''}</td>"
        f"<td>{esc(row['kind'])}</td><td><span class=\"status\">{esc(row['status'])}</span></td>"
        f"<td>{esc((row['text'] or '')[:100])}</td>"
        "</tr>"
        for row in posts
    )
    user_details = db_rows("""
        SELECT u.*, COUNT(p.id) AS posts_count,
               MAX(p.created_at) AS last_post_at
        FROM users u LEFT JOIN posts p ON p.user_id = u.user_id
        GROUP BY u.user_id ORDER BY u.last_seen DESC LIMIT 500
    """)
    user_detail_rows = "".join(
        f"<tr class='detail-user-row'><td><a class=\"button-link\" href=\"/user?id={esc(row['user_id'])}\"><code>{esc(row['user_id'])}</code></a></td>"
        f"<td>{esc(row['first_name'])} {esc(row['last_name'])}</td>"
        f"<td>{('@' + row['username']) if row['username'] else '—'}</td>"
        f"<td>{esc(row['language_code'])}</td><td>{esc(row['ui_lang'])}</td>"
        f"<td>{'Да' if row['is_premium'] else 'Нет'}</td><td>{esc(row['posts_count'])}</td>"
        f"<td>{datetime.fromtimestamp(row['last_seen']).strftime('%d.%m.%Y %H:%M:%S') if row['last_seen'] else '—'}</td></tr>"
        for row in user_details
    )
    approval = ""
    if owner or can_access(current_user, "actions"):
        actions = db_rows("SELECT actor, action, target, created_at FROM dashboard_actions ORDER BY created_at DESC LIMIT 100")
        action_rows = "".join(
            f"<tr><td>{datetime.fromtimestamp(row['created_at']).strftime('%d.%m.%Y %H:%M:%S')}</td><td>{esc(row['actor'])}</td><td>{esc(row['action'])}</td><td>{esc(row['target'])}</td></tr>"
            for row in actions
        )
        actions_section = f"""<section id="actions"><h2>Действия администраторов</h2><div class="table-wrap"><table><tr><th>Время</th><th>Администратор</th><th>Действие</th><th>Объект</th></tr>{action_rows or '<tr><td colspan=4>Действий пока нет</td></tr>'}</table></div></section>"""
        approval = actions_section if section == "actions" else ""
        if owner:
            pending = db_rows("SELECT username, created_at FROM dashboard_users WHERE status='pending' ORDER BY created_at")
            rows = "".join(
                f"<tr><td>{esc(row['username'])}</td><td>{datetime.fromtimestamp(row['created_at']).strftime('%d.%m.%Y %H:%M')}</td>"
                f"<td><form class='inline' method='post' action='/approve'><input type='hidden' name='username' value='{esc(row['username'])}'><button>Одобрить</button></form>"
                f"<form class='inline' method='post' action='/reject'><input type='hidden' name='username' value='{esc(row['username'])}'><button class='danger'>Отклонить</button></form></td></tr>"
                for row in pending
            )
            owners = db_rows("SELECT username, created_at FROM dashboard_users WHERE role='owner' AND status='approved' ORDER BY username")
            owner_rows = "".join(
                f"<tr><td>{esc(row['username'])}</td><td>{datetime.fromtimestamp(row['created_at']).strftime('%d.%m.%Y %H:%M')}</td></tr>"
                for row in owners
            )
            approval = {
                "access": f"""<section id="access"><h2>Заявки на доступ</h2><div class="table-wrap"><table><tr><th>Логин</th><th>Дата</th><th>Действие</th></tr>{rows or '<tr><td colspan=3>Новых заявок нет</td></tr>'}</table></div></section>""",
                "owners": f"""<section id="owners"><h2>Владельцы</h2><form class="owner-form" method="post" action="/add-owner"><input name="username" placeholder="Логин нового владельца" required minlength="3"><input name="password" type="password" placeholder="Пароль нового владельца" required minlength="8"><button>Добавить владельца</button></form><div class="table-wrap"><table><tr><th>Логин</th><th>Добавлен</th></tr>{owner_rows or '<tr><td colspan=2>Дополнительных владельцев нет</td></tr>'}</table></div></section>""",
                "actions": actions_section,
            }.get(section, "")
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<title>Podslushka DB</title><style>
:root{{--bg:#090b1c;--sidebar:#11132d;--panel:#191c3b;--panel2:#222550;--line:#353866;--text:#f5f4ff;--muted:#a5a8c7;--blue:#7b61ff;--blue2:#27d3c2;--danger:#ef5c87}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:radial-gradient(circle at 78% 0,#714dff2b,transparent 30%),radial-gradient(circle at 20% 100%,#17d6c51d,transparent 28%),var(--bg);color:var(--text);font:14px Inter,Segoe UI,Arial,sans-serif}}
.layout{{display:flex;min-height:100vh;perspective:1500px}}.sidebar{{position:fixed;inset:0 auto 0 0;width:255px;padding:25px 16px;background:linear-gradient(180deg,#171943,#0d1028);border-right:1px solid #38366d;z-index:50;pointer-events:auto;box-shadow:10px 0 24px #02071188,12px 0 45px #6e52ff18}}
.brand{{display:flex;align-items:center;gap:11px;padding:4px 10px 28px;font-size:19px;font-weight:800;letter-spacing:-.4px}}.logo{{display:grid;place-items:center;width:36px;height:36px;border-radius:11px;background:linear-gradient(135deg,#a98bff,#6450ed);box-shadow:5px 6px 0 #34268d,0 8px 22px #7b61ff88;font-size:19px;transform:translateZ(16px)}}
.menu-title{{padding:0 11px 9px;color:#7085a3;text-transform:uppercase;font-size:10px;font-weight:800;letter-spacing:1px}}.nav{{display:grid;gap:7px}}.nav a{{position:relative;z-index:60;display:flex;align-items:center;gap:11px;padding:12px 11px;border:1px solid transparent;border-radius:10px;color:#adc0d9;text-decoration:none;font-weight:600;transition:.18s;transform-style:preserve-3d;pointer-events:auto}}.nav a:hover,.nav a.active{{color:#fff;background:linear-gradient(135deg,#353276,#202957);border-color:#695ce0;box-shadow:5px 6px 0 #0a1027,0 0 22px #7b61ff33;transform:translate(-2px,-2px)}}.nav a:focus-visible{{outline:3px solid var(--blue2);outline-offset:3px}}.nav .icon{{width:20px;text-align:center;font-size:16px}}
.sidebar-footer{{position:absolute;bottom:22px;left:25px;right:25px;color:#6f85a3;font-size:11px;line-height:1.55}}.content{{width:100%;margin-left:255px;padding:34px clamp(22px,4vw,58px) 60px}}.topbar{{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;margin-bottom:25px}}h1{{margin:0 0 7px;font-size:30px;letter-spacing:-.8px}}h2{{margin:42px 0 15px;font-size:21px;letter-spacing:-.3px}}.muted{{color:var(--muted)}}
.cards{{display:grid;grid-template-columns:repeat(6,1fr);gap:13px;margin:0 0 27px}}.card{{background:linear-gradient(145deg,#252953,#171a39);border:1px solid #454783;border-radius:15px;padding:17px;box-shadow:7px 8px 0 #080a1b,0 12px 30px #03091455,0 0 24px #7b61ff12;transition:.2s;transform:translateZ(8px)}}.card:hover{{transform:translateY(-5px) rotateX(3deg) rotateY(-2deg);box-shadow:9px 12px 0 #080a1b,0 18px 34px #03091488,0 0 30px #7b61ff2b}}.card b{{display:block;color:#a7aad0;font-size:12px;font-weight:600}}.card strong{{display:block;font-size:28px;margin-top:9px;color:#f9f8ff}}
.toolbar{{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 25px;padding:15px;background:linear-gradient(145deg,#191c3b,#11142c);border:1px solid #393d70;border-radius:14px;box-shadow:7px 8px 0 #080a1b,0 10px 28px #03091455}}input,select{{background:#0e192b;color:#e2e8f0;border:1px solid #3a5272;border-radius:9px;padding:11px 13px;min-width:220px;outline:none}}input:focus,select:focus{{border-color:var(--blue);box-shadow:0 0 0 3px #4f8cff22}}button,input[type=submit],a.button-link{{position:relative;z-index:60;pointer-events:auto;display:inline-block;background:linear-gradient(145deg,#876eff,#3e6fe8);color:white;border:0;border-radius:9px;padding:10px 15px;font-weight:700;cursor:pointer;transition:transform .18s,filter .18s,box-shadow .18s;text-decoration:none;box-shadow:0 5px 0 #34268d,0 10px 18px #7b61ff33;transform:translateY(0);transform-style:preserve-3d}}button:hover,input[type=submit]:hover,a.button-link:hover{{filter:brightness(1.1);transform:translateY(-2px);box-shadow:0 7px 0 #34268d,0 14px 24px #7b61ff44}}button:active,input[type=submit]:active,a.button-link:active{{transform:translateY(3px);box-shadow:0 2px 0 #34268d}}button:focus-visible,input[type=submit]:focus-visible,a.button-link:focus-visible{{outline:3px solid var(--blue2);outline-offset:3px}}button:disabled,input[type=submit]:disabled{{opacity:.5;cursor:not-allowed;transform:none;box-shadow:0 3px 0 #252848}}.danger{{background:linear-gradient(135deg,#c84d5a,#a83240);box-shadow:0 5px 0 #702933,0 10px 18px #c84d5a33}}.button-link code{{color:inherit}}
.table-wrap{{overflow:auto;background:linear-gradient(145deg,#1b2940,#172438);border:1px solid #2d4565;border-radius:14px;box-shadow:7px 8px 0 #080f1e,0 12px 30px #03091435;transform:translateZ(4px)}}table{{border-collapse:collapse;width:100%;min-width:850px}}th,td{{padding:13px 14px;text-align:left;border-bottom:1px solid #2b405f}}th{{color:#8fc0ff;background:#18263b;position:sticky;top:0;font-size:12px;text-transform:uppercase;letter-spacing:.3px}}tr:last-child td{{border-bottom:0}}tr:hover{{background:#243650}}code{{color:#a7f3d0}}.status{{padding:4px 9px;border-radius:20px;background:#304664;color:#d7e8ff;font-size:12px}}
.empty{{display:none;color:#94a3b8;padding:16px}}.inline{{display:inline}}.inline button{{margin:2px 4px 2px 0}}.owner-form{{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 16px}}.owner-form input{{min-width:220px}}section{{scroll-margin-top:20px}}
@media(max-width:1150px){{.cards{{grid-template-columns:repeat(3,1fr)}}}}@media(max-width:700px){{.sidebar{{position:relative;width:100%;padding:16px;min-height:0;border-right:0;border-bottom:1px solid #243956}}.layout{{display:block}}.content{{margin-left:0;padding:25px 16px 45px}}.sidebar-footer{{display:none}}.brand{{padding-bottom:17px}}.nav{{grid-template-columns:repeat(2,1fr)}}.nav a{{padding:10px;font-size:12px}}.topbar{{display:block}}.cards{{grid-template-columns:repeat(2,1fr);gap:9px}}.card{{padding:13px}}.card strong{{font-size:23px}}h1{{font-size:25px}}}}
</style></head><body><div class="layout">
<aside class="sidebar"><div class="brand"><span class="logo">◈</span><span>Podslushka DB</span></div><div class="menu-title">Навигация</div><nav class="nav">
<a class="{'active' if section == 'overview' else ''}" href="/"><span class="icon">⌂</span>Обзор</a><a class="{'active' if section in ('users', 'user-search') else ''}" href="/?view=users"><span class="icon">♙</span>Пользователи</a><a class="{'active' if section == 'posts' else ''}" href="/?view=posts"><span class="icon">▤</span>Заявки</a>
<a class="{'active' if section == 'user-search' else ''}" href="/?view=user-search"><span class="icon">⌕</span>Поиск пользователей</a>
{('<a class="' + ('active' if section == 'access' else '') + '" href="/?view=access"><span class="icon">✓</span>Доступ</a><a class="' + ('active' if section == 'actions' else '') + '" href="/?view=actions"><span class="icon">◷</span>Журнал действий</a><a class="' + ('active' if section == 'owners' else '') + '" href="/?view=owners"><span class="icon">♛</span>Владельцы</a>' if owner else '')}
</nav><div class="sidebar-footer">Защищённая панель управления<br>Автообновление каждые 30 секунд</div></aside>
<main class="content"><div class="topbar"><div><h1>Панель управления</h1><div class="muted">Мониторинг базы данных и модерации · роль: <b>{esc(role)}</b></div></div><div><a class="button-link" href="/export/users.csv">↓ CSV</a> <a href="/logout"><button class="danger">Выйти</button></a></div></div>
{('<section id="overview"><div class="cards">' + cards + '</div></section>' if section == 'overview' else '')}
{('<div class="toolbar"><input id="search" placeholder="Поиск: имя, username, ID, текст..." autocomplete="off"><select id="status"><option value="">Все статусы</option><option value="pending">На модерации</option><option value="published">Опубликовано</option><option value="rejected">Отклонено</option><option value="deleted">Удалено</option></select><button type="button" onclick="refreshPage()">↻ Обновить</button><a class="button-link" href="/backup">↓ Резервная копия</a></div>' if section == 'overview' else '')}
{('<section id="users"><h2>Пользователи <span class="muted" id="user-count"></span></h2><div class="table-wrap"><table><tr><th>ID</th><th>Имя</th><th>Username</th><th>Язык</th><th>Заявок</th><th>Последний контакт</th></tr>' + user_rows + '</table><div class="empty" id="users-empty">Ничего не найдено</div></div></section><section id="posts"><h2>Последние заявки <span class="muted" id="post-count"></span></h2><div class="table-wrap"><table><tr><th>ID</th><th>User ID</th><th>Автор</th><th>Тип</th><th>Статус</th><th>Текст</th></tr>' + post_rows + '</table><div class="empty" id="posts-empty">Ничего не найдено</div></div></section>' if section == 'overview' else '')}
{('<section id="users"><h2>Все пользователи</h2><div class="toolbar"><input id="detail-search" placeholder="Поиск по ID, имени, username..." autocomplete="off"></div><div class="table-wrap"><table><tr><th>ID</th><th>Имя</th><th>Username</th><th>Язык</th><th>Язык панели</th><th>Premium</th><th>Заявок</th><th>Последний контакт</th></tr>' + user_detail_rows + '</table><div class="empty" id="detail-empty">Пользователи не найдены</div></div></section>' if section == 'users' else '')}
{('<section id="posts"><h2>Все заявки</h2><div class="table-wrap"><table><tr><th>ID</th><th>User ID</th><th>Автор</th><th>Тип</th><th>Статус</th><th>Текст</th></tr>' + post_rows + '</table></div></section>' if section == 'posts' else '')}
{('<section id="user-search"><h2>Поиск пользователя</h2><div class="toolbar"><input id="detail-search" placeholder="Введите ID, имя или username..." autocomplete="off"></div><div class="table-wrap"><table><tr><th>ID</th><th>Имя</th><th>Username</th><th>Язык</th><th>Язык панели</th><th>Premium</th><th>Заявок</th><th>Последний контакт</th></tr>' + user_detail_rows + '</table><div class="empty" id="detail-empty">Пользователи не найдены</div></div></section>' if section == 'user-search' else '')}
{approval}
</main></div><script>
const search = document.getElementById('search');
const status = document.getElementById('status');
const detailSearch = document.getElementById('detail-search');
function filterRows() {{
  const liveSearch = document.getElementById('search');
  const liveStatus = document.getElementById('status');
  const q = liveSearch.value.toLowerCase().trim();
  const selected = liveStatus.value;
  let users = 0, posts = 0;
  document.querySelectorAll('.user-row').forEach(row => {{
    const visible = !q || row.innerText.toLowerCase().includes(q);
    row.style.display = visible ? '' : 'none';
    if (visible) users++;
  }});
  document.querySelectorAll('.post-row').forEach(row => {{
    const visible = (!q || row.innerText.toLowerCase().includes(q)) &&
      (!selected || row.dataset.status === selected);
    row.style.display = visible ? '' : 'none';
    if (visible) posts++;
  }});
  document.getElementById('user-count').textContent = `(${{users}} найдено)`;
  document.getElementById('post-count').textContent = `(${{posts}} найдено)`;
  document.getElementById('users-empty').style.display = users ? 'none' : 'block';
  document.getElementById('posts-empty').style.display = posts ? 'none' : 'block';
}}
function filterDetails() {{
  const liveDetailSearch = document.getElementById('detail-search');
  const q = liveDetailSearch.value.toLowerCase().trim();
  let count = 0;
  document.querySelectorAll('.detail-user-row').forEach(row => {{
    const visible = !q || row.innerText.toLowerCase().includes(q);
    row.style.display = visible ? '' : 'none';
    if (visible) count++;
  }});
  document.getElementById('detail-empty').style.display = count ? 'none' : 'block';
}}
function bindControls() {{
  const liveSearch = document.getElementById('search');
  const liveStatus = document.getElementById('status');
  const liveDetailSearch = document.getElementById('detail-search');
  if (liveSearch && liveStatus) {{
    liveSearch.addEventListener('input', filterRows);
    liveStatus.addEventListener('change', filterRows);
    filterRows();
  }}
  if (liveDetailSearch) {{
    liveDetailSearch.addEventListener('input', filterDetails);
    filterDetails();
  }}
}}
bindControls();
async function refreshPage() {{
  const scrollY = window.scrollY;
  const focusKey = document.activeElement && (document.activeElement.id || document.activeElement.name);
  const formState = {{}};
  document.querySelectorAll('input,select,textarea').forEach(field => {{
    const key = field.id || field.name;
    if (!key) return;
    formState[key] = field.type === 'checkbox' || field.type === 'radio'
      ? field.checked : field.value;
  }});
  const oldHash = location.hash;
  try {{
    const response = await fetch(location.href, {{cache: 'no-store'}});
    if (!response.ok) return;
    const html = await response.text();
    const parsed = new DOMParser().parseFromString(html, 'text/html');
    const next = parsed.querySelector('.content');
    const current = document.querySelector('.content');
    if (next && current) {{
      current.replaceWith(next);
      document.querySelectorAll('input,select,textarea').forEach(field => {{
        const key = field.id || field.name;
        if (!(key in formState)) return;
        if (field.type === 'checkbox' || field.type === 'radio') field.checked = formState[key];
        else field.value = formState[key];
      }});
      window.scrollTo(0, scrollY);
      if (oldHash) location.hash = oldHash.slice(1);
      bindControls();
      if (focusKey) {{
        const focused = document.getElementById(focusKey) || document.querySelector(`[name="${{CSS.escape(focusKey)}}"]`);
        if (focused) focused.focus({{preventScroll: true}});
      }}
    }}
  }} catch (_) {{}}
}}
async function watchForUpdates() {{
  try {{
    const response = await fetch('/api/state', {{cache: 'no-store'}});
    if (!response.ok) return;
    const state = await response.json();
    const current = document.body.dataset.lastUpdate || '';
    if (current && state.updated !== current) await refreshPage();
    document.body.dataset.lastUpdate = state.updated || '';
  }} catch (_) {{
    // A temporary network failure is retried on the next poll.
  }}
}}
watchForUpdates();
setInterval(watchForUpdates, 1500);
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def send_html(self, content: str, status: int = 200) -> None:
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/logout":
            actor = auth_user(self)
            token = destroy_session(self)
            if actor:
                log_action(actor, "Logout", "")
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "session=; Max-Age=0; HttpOnly; SameSite=Strict")
            self.end_headers()
            return
        # OAuth endpoints are deliberately available before a dashboard session.
        # A verified identity is shown to the user, but is not silently converted into
        # a dashboard account until an explicit account-linking backend exists.
        if path == "/auth/google":
            if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and OAUTH_BASE_URL):
                log_action("anonymous", "OAuth google failed", "disabled")
                self.send_html(auth_page("Google OAuth is disabled: set the OAuth environment variables."))
                return
            state = oauth_state("google")
            query = urllib.parse.urlencode({
                "client_id": GOOGLE_CLIENT_ID,
                "redirect_uri": oauth_redirect("google"),
                "response_type": "code",
                "scope": "openid email profile",
                "state": state,
                "access_type": "offline",
                "prompt": "select_account",
            })
            self.send_response(302)
            self.send_header("Location", "https://accounts.google.com/o/oauth2/v2/auth?" + query)
            self.end_headers()
            return
        if path == "/auth/google/callback":
            query = parse_qs(parsed.query)
            if not consume_oauth_state(query.get("state", [""])[0], "google"):
                log_action("google:unknown", "OAuth google failed", "invalid_state")
                self.send_html(auth_page("OAuth state expired or invalid. Start sign-in again."), 400)
                return
            code = query.get("code", [""])[0]
            if not code:
                log_action("google:unknown", "OAuth google failed", "missing_code")
                self.send_html(auth_page("Google did not return an authorization code."), 400)
                return
            try:
                payload = urllib.parse.urlencode({
                    "code": code,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": oauth_redirect("google"),
                    "grant_type": "authorization_code",
                }).encode("utf-8")
                request = urllib.request.Request("https://oauth2.googleapis.com/token", data=payload, method="POST")
                with urllib.request.urlopen(request, timeout=10) as response:
                    token_data = json.loads(response.read().decode("utf-8"))
                access_token = token_data.get("access_token")
                if not access_token:
                    raise ValueError("Google did not return an access token")
                request = urllib.request.Request(
                    "https://openidconnect.googleapis.com/v1/userinfo",
                    headers={"Authorization": "Bearer " + access_token},
                )
                with urllib.request.urlopen(request, timeout=10) as response:
                    identity = json.loads(response.read().decode("utf-8"))
                if identity.get("email_verified") is False:
                    raise ValueError("Google email is not verified")
                complete_oauth(
                    self, "google", identity.get("sub"),
                    identity.get("email", ""), identity.get("name", ""),
                )
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                logging.warning("Google OAuth failed: %s", exc)
                log_action("google:unknown", "OAuth google failed", str(exc)[:240])
                self.send_html(auth_page("Google sign-in failed. Check the callback URL and OAuth keys."), 400)
            return
        if path == "/auth/telegram/callback":
            query = parse_qs(parsed.query)
            if not telegram_login_valid(query):
                log_action("telegram:unknown", "OAuth telegram failed", "invalid_signature")
                self.send_html(auth_page("Telegram Login is disabled or the signature is invalid."), 400)
                return
            telegram_id = query.get("id", [""])[0]
            telegram_name = query.get("username", query.get("first_name", ["Telegram user"]))[0]
            try:
                complete_oauth(
                    self, "telegram", telegram_id,
                    query.get("username", [""])[0], telegram_name,
                )
            except (ValueError,) + DB_ERRORS as exc:
                log_action(f"telegram:{telegram_id or 'unknown'}", "OAuth telegram failed", str(exc)[:240])
                self.send_html(auth_page("Telegram sign-in failed. Try again."), 400)
            return
        if not auth_user(self):
            body = auth_page().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/state":
            updated = scalar("SELECT MAX(created_at) FROM posts") or 0
            updated = max(updated, scalar("SELECT MAX(last_seen) FROM users") or 0)
            body = json.dumps({"updated": str(updated)}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/bot-status":
            if not is_owner(auth_user(self)):
                self.send_error(403)
                return
            body = json.dumps(BOT_STATUS).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/user":
            try:
                user_id = int(parse_qs(parsed.query).get("id", [""])[0])
            except ValueError:
                self.send_error(400, "A numeric user id is required")
                return
            body = user_detail_page(auth_user(self) or "", user_id)
            if not body:
                self.send_error(404)
                return
            self.send_html(body)
            return
        if path == "/export/users.csv":
            if not can_access(auth_user(self), "export"):
                self.send_error(403)
                return
            log_action(auth_user(self) or "unknown", "Export users CSV", "users")
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["user_id", "first_name", "last_name", "username", "language_code",
                             "ui_lang", "is_premium", "posts", "banned", "warns", "last_seen"])
            rows = db_rows(
                """SELECT u.user_id, u.first_name, u.last_name, u.username,
                          u.language_code, u.ui_lang, u.is_premium,
                          COUNT(DISTINCT p.id) AS posts_count,
                          CASE WHEN b.user_id IS NULL THEN 0 ELSE 1 END AS banned,
                          COUNT(DISTINCT w.id) AS warns_count, u.last_seen
                   FROM users u
                   LEFT JOIN posts p ON p.user_id=u.user_id
                   LEFT JOIN bans b ON b.user_id=u.user_id
                   LEFT JOIN warns w ON w.user_id=u.user_id
                   GROUP BY u.user_id, u.first_name, u.last_name, u.username,
                            u.language_code, u.ui_lang, u.is_premium, b.user_id, u.last_seen
                   ORDER BY u.user_id"""
            )
            for row in rows:
                writer.writerow([row[key] for key in (
                    "user_id", "first_name", "last_name", "username", "language_code",
                    "ui_lang", "is_premium", "posts_count", "banned", "warns_count", "last_seen"
                )])
            body = output.getvalue().encode("utf-8-sig")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=podslushka-users.csv")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/":
            requested_section = parse_qs(parsed.query).get("view", ["overview"])[0]
            body = page(auth_user(self) or "", requested_section).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        elif path == "/backup":
            actor = auth_user(self)
            if not can_access(actor, "export"):
                self.send_error(403)
                return
            if DATABASE_URL:
                body = (
                    "PostgreSQL is persistent and backed up by the managed database service."
                ).encode("utf-8")
            else:
                backup = ROOT / "backups"
                backup.mkdir(exist_ok=True)
                target = backup / f"podslushka_{datetime.now():%Y%m%d_%H%M%S}.db"
                shutil.copy2(DB_PATH, target)
                body = f"Резервная копия создана: {target.name}".encode("utf-8")
            log_action(actor or "unknown", "Backup database", "podslushka")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        else:
            self.send_error(404)
            return
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length)
        if path == "/api/sync":
            if not SYNC_SECRET or not secrets.compare_digest(
                self.headers.get("X-Sync-Secret", ""), SYNC_SECRET
            ):
                log_action("bot-sync", "Sync rejected", self.client_address[0] if self.client_address else "")
                self.send_error(403)
                return
            try:
                payload = json.loads(raw_body.decode("utf-8"))
                with db_connect() as conn:
                    for user in payload.get("users", []):
                        conn.execute(
                            """INSERT INTO users
                               (user_id, first_name, last_name, username, language_code,
                                is_premium, ui_lang, first_seen, last_seen)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                               ON CONFLICT(user_id) DO UPDATE SET
                                 first_name=COALESCE(excluded.first_name, users.first_name),
                                 last_name=COALESCE(excluded.last_name, users.last_name),
                                 username=COALESCE(excluded.username, users.username),
                                 language_code=COALESCE(excluded.language_code, users.language_code),
                                 is_premium=COALESCE(excluded.is_premium, users.is_premium),
                                 ui_lang=COALESCE(excluded.ui_lang, users.ui_lang),
                                 first_seen=COALESCE(excluded.first_seen, users.first_seen),
                                 last_seen=COALESCE(excluded.last_seen, users.last_seen)""",
                            (
                                user["user_id"], user.get("first_name"), user.get("last_name"),
                                user.get("username"), user.get("language_code"),
                                user.get("is_premium"), user.get("ui_lang"),
                                user.get("first_seen"), user.get("last_seen"),
                            ),
                        )
                    for post in payload.get("posts", []):
                        conn.execute(
                            """INSERT INTO posts
                               (id, user_id, kind, text, status, public_id, created_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?)
                               ON CONFLICT(id) DO UPDATE SET
                                user_id=COALESCE(excluded.user_id, posts.user_id),
                                kind=COALESCE(excluded.kind, posts.kind),
                                text=COALESCE(excluded.text, posts.text),
                                status=COALESCE(excluded.status, posts.status),
                                public_id=COALESCE(excluded.public_id, posts.public_id),
                                created_at=COALESCE(excluded.created_at, posts.created_at)""",
                            (
                                post["id"], post.get("user_id"), post.get("kind"),
                                post.get("text"), post.get("status"),
                                post.get("public_id"), post.get("created_at"),
                            ),
                        )
                    if DATABASE_URL and payload.get("posts"):
                        conn.execute(
                            """SELECT setval(
                                pg_get_serial_sequence('posts', 'id'),
                                COALESCE((SELECT MAX(id) FROM posts), 1),
                                true
                            )"""
                        )
                    conn.commit()
                body = b'{"ok":true}'
                log_action(
                    "bot-sync", "Sync completed",
                    f"users={len(payload.get('users', []))},posts={len(payload.get('posts', []))}",
                )
            except (ValueError, KeyError, TypeError) + DB_ERRORS:
                log_action("bot-sync", "Sync failed", "invalid_payload")
                self.send_error(400, "Invalid sync payload")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        fields = parse_qs(raw_body.decode("utf-8"))
        username = fields.get("username", [""])[0].strip()
        password = fields.get("password", [""])[0]
        otp = fields.get("otp", [""])[0].strip()
        error = ""
        if path == "/register":
            if len(username) < 3 or len(password) < 8:
                error = "Логин от 3 символов, пароль минимум 8 символов."
            else:
                try:
                    with db_connect() as conn:
                        conn.execute(
                            "INSERT INTO dashboard_users (username, password_hash, status, created_at) VALUES (?, ?, 'pending', ?)",
                            (username, password_hash(password), int(datetime.now().timestamp())),
                        )
                        conn.commit()
                except DB_INTEGRITY_ERRORS:
                    error = "Такой логин уже зарегистрирован."
            if not error:
                log_action(username, "Register access request", username)
                body = auth_page("Заявка отправлена. Владелец должен одобрить доступ перед входом.").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            log_action(username or "anonymous", "Register access failed", username)
        elif path == "/approve":
            actor = auth_user(self)
            if not is_owner(actor):
                log_action(actor or "anonymous", "Approve access denied", username)
                self.send_error(403)
                return
            with db_connect() as conn:
                conn.execute("UPDATE dashboard_users SET status='approved' WHERE username=?", (username,))
                conn.commit()
            log_action(actor or "owner", "Approve access", username)
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        elif path == "/reject":
            actor = auth_user(self)
            if not is_owner(actor):
                log_action(actor or "anonymous", "Reject access denied", username)
                self.send_error(403)
                return
            with db_connect() as conn:
                conn.execute("UPDATE dashboard_users SET status='rejected' WHERE username=?", (username,))
                conn.commit()
            log_action(actor or "owner", "Reject access", username)
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        elif path == "/add-owner":
            actor = auth_user(self)
            if not is_owner(actor):
                log_action(actor or "anonymous", "Add owner denied", username)
                self.send_error(403)
                return
            if len(username) < 3 or len(password) < 8:
                error = "Логин владельца от 3 символов, пароль минимум 8 символов."
            else:
                try:
                    with db_connect() as conn:
                        conn.execute(
                            "INSERT INTO dashboard_users (username, password_hash, status, role, created_at) VALUES (?, ?, 'approved', 'owner', ?)",
                            (username, password_hash(password), int(datetime.now().timestamp())),
                        )
                        conn.commit()
                    log_action(actor or "owner", "Добавил владельца", username)
                except DB_INTEGRITY_ERRORS:
                    error = "Такой логин уже существует."
                    log_action(actor or "owner", "Add owner failed", username)
            if not error:
                self.send_response(302)
                self.send_header("Location", "/#owners")
                self.end_headers()
                return
        elif path == "/login":
            if not login_allowed(self, username):
                log_action(username or "anonymous", "Login rate limited", username)
                error = "Слишком много попыток входа. Повторите через 15 минут."
                row = None
                owner_login = False
            else:
                with db_connect(readonly=True) as conn:
                    row = conn.execute(
                        "SELECT password_hash, status, totp_secret FROM dashboard_users WHERE username = ?", (username,)
                    ).fetchone()
                owner_login = (
                    username == OWNER_USERNAME and OWNER_PASSWORD
                    and secrets.compare_digest(password, OWNER_PASSWORD)
                )
                configured_totp = OWNER_2FA_SECRET if OWNER_2FA_REQUIRED else ""
                if row and row_value(row, "totp_secret", 2):
                    configured_totp = row_value(row, "totp_secret", 2) if OWNER_2FA_REQUIRED else ""
                valid_password = owner_login or (
                    bool(row)
                    and row_value(row, "status", 1) == "approved"
                    and verify_password(password, row_value(row, "password_hash", 0))
                )
                if not valid_password or not totp_valid(configured_totp, otp):
                    record_login_attempt(self, username, False)
                    log_action(username or "anonymous", "Login failed", username)
                    error = "Неверный логин, пароль, код 2FA или доступ ещё не одобрен владельцем."
                else:
                    record_login_attempt(self, username, True)
        else:
            self.send_error(404)
            return
        if error:
            body = auth_page(error).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        token = create_session(username, self)
        if owner_login:
            log_action(username, "Login success (owner)", "")
        else:
            log_action(username, "Login success", "")
        self.send_response(302)
        self.send_header("Location", "/")
        secure = "; Secure" if OAUTH_BASE_URL.startswith("https://") else ""
        self.send_header("Set-Cookie", f"session={token}; HttpOnly; SameSite=Strict{secure}")
        self.end_headers()

    def log_message(self, *_):
        return


if __name__ == "__main__":
    init_auth()
    start_embedded_bot()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    public_host = "127.0.0.1" if HOST == "0.0.0.0" else HOST
    url = f"http://{public_host}:{PORT}/"
    print(f"DB viewer: {url}")
    if HOST == "127.0.0.1":
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
    finally:
        if BOT_PROCESS and BOT_PROCESS.poll() is None:
            BOT_PROCESS.terminate()

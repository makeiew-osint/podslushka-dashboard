from __future__ import annotations

import html
import hashlib
import os
import secrets
import shutil
import sqlite3
import threading
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "podslushka.db"
HOST = os.getenv("HOST", "0.0.0.0" if os.getenv("PORT") else "127.0.0.1")
PORT = int(os.getenv("PORT", "8765"))
SESSIONS: dict[str, str] = {}
OWNER_USERNAME = os.getenv("OWNER_USERNAME", "")
OWNER_PASSWORD = os.getenv("OWNER_PASSWORD", "")


def esc(value) -> str:
    return html.escape("—" if value is None else str(value))


def db_rows(query: str, params=()):
    with sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(query, params).fetchall()


def scalar(query: str):
    rows = db_rows(query)
    return rows[0][0] if rows else 0


def init_auth() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at INTEGER NOT NULL
            )
        """)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(dashboard_users)")}
        if "status" not in columns:
            conn.execute("ALTER TABLE dashboard_users ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
        conn.execute("CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY, first_name TEXT, last_name TEXT, username TEXT, language_code TEXT, is_premium INTEGER DEFAULT 0, ui_lang TEXT, first_seen INTEGER, last_seen INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, kind TEXT, text TEXT, status TEXT DEFAULT 'pending', created_at INTEGER, public_id INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS bans (user_id INTEGER PRIMARY KEY, reason TEXT, created_at INTEGER)")
        conn.execute("CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER, reason TEXT, created_at INTEGER)")
        conn.commit()


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split("$", 1)
    expected = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 200_000
    ).hex()
    return secrets.compare_digest(expected, digest_hex)


def auth_user(handler: BaseHTTPRequestHandler) -> str | None:
    cookie = handler.headers.get("Cookie", "")
    token = next((item.split("=", 1)[1] for item in cookie.split("; ")
                  if item.startswith("session=")), None)
    return SESSIONS.get(token) if token else None


def is_owner(username: str | None) -> bool:
    return bool(username and OWNER_USERNAME and username == OWNER_USERNAME)


def auth_page(message: str = "") -> str:
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Вход · Podslushka</title><style>
:root{{--bg:#0b1220;--panel:#162238;--line:#2b405f;--text:#edf5ff;--muted:#91a4bf;--blue:#4f8cff;--blue2:#6ca0ff}}
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;
background:radial-gradient(circle at 15% 15%,#193664 0,transparent 35%),radial-gradient(circle at 90% 85%,#172d57 0,transparent 32%),var(--bg);
color:var(--text);font:15px Inter,Segoe UI,Arial,sans-serif}}
.shell{{width:min(920px,100%);display:grid;grid-template-columns:1fr 1fr;overflow:hidden;border:1px solid #2a4265;
border-radius:24px;background:rgba(22,34,56,.88);box-shadow:0 24px 80px #0008;backdrop-filter:blur(14px)}}
.intro{{padding:48px 42px;background:linear-gradient(145deg,#1b3966,#14243d);position:relative;overflow:hidden}}
.intro:after{{content:"";position:absolute;width:240px;height:240px;border-radius:50%;right:-100px;bottom:-120px;background:#5c9aff22}}
.brand{{display:flex;align-items:center;gap:12px;font-weight:800;font-size:22px;letter-spacing:-.5px}}
.logo{{width:44px;height:44px;display:grid;place-items:center;border-radius:13px;background:linear-gradient(135deg,#70a7ff,#3d6cf0);font-size:23px;box-shadow:0 8px 24px #2f6fff55}}
.intro h1{{font-size:35px;line-height:1.08;margin:58px 0 16px;letter-spacing:-1.5px}}
.intro p{{color:#b7c8de;line-height:1.65;max-width:320px}}.features{{margin-top:34px;display:grid;gap:13px;color:#d7e6fa}}
.feature{{display:flex;gap:10px;align-items:center}}.check{{color:#83b2ff;font-size:18px}}
.auth{{padding:42px 40px;background:#111c2e}}.auth h2{{margin:0 0 8px;font-size:25px}}
.sub{{color:var(--muted);margin:0 0 26px}}.error{{min-height:22px;margin:0 0 9px;color:#ff9eaa;font-size:13px}}
.tabs{{display:grid;grid-template-columns:1fr 1fr;gap:5px;padding:4px;margin-bottom:22px;background:#0b1423;border-radius:10px}}
.tab{{border:0;background:transparent;color:var(--muted);padding:10px;border-radius:7px;font-weight:700;cursor:pointer}}
.tab.active{{background:#263e63;color:#fff}}.form{{display:none}}.form.active{{display:block}}
.field{{display:block;margin:15px 0 6px;color:#a9bbd3;font-size:13px;font-weight:600}}
.input-wrap{{position:relative}}input{{width:100%;padding:13px 43px 13px 14px;border-radius:10px;border:1px solid var(--line);
background:#0c1729;color:#fff;outline:none;font-size:15px;transition:.2s}}input:focus{{border-color:var(--blue);box-shadow:0 0 0 3px #4f8cff22}}
.toggle{{position:absolute;right:10px;top:9px;border:0;background:transparent;color:#7f95b5;cursor:pointer;font-size:17px}}
.submit{{width:100%;margin-top:22px;padding:13px;border:0;border-radius:10px;background:linear-gradient(135deg,var(--blue),#3e6fe8);
color:white;font-weight:800;font-size:15px;cursor:pointer;box-shadow:0 8px 20px #3975ed44;transition:.2s}}
.submit:hover{{transform:translateY(-1px);filter:brightness(1.08)}}.hint{{margin:20px 0 0;text-align:center;color:#7085a3;font-size:12px}}
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
<label class="field">Пароль</label><div class="input-wrap"><input name="password" type="password" placeholder="Введите пароль" required autocomplete="current-password"><button type="button" class="toggle">◉</button></div><button class="submit" type="submit">Войти в панель →</button></form>
<form class="form" id="register" method="post" action="/register"><label class="field">Логин</label><input name="username" placeholder="Придумайте логин" required minlength="3" autocomplete="username">
<label class="field">Пароль</label><div class="input-wrap"><input name="password" type="password" placeholder="Минимум 8 символов" required minlength="8" autocomplete="new-password"><button type="button" class="toggle">◉</button></div><button class="submit" type="submit">Создать аккаунт →</button></form>
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


def page(current_user: str = "") -> str:
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
        GROUP BY u.user_id ORDER BY u.last_seen DESC LIMIT 100
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
        f"<td><code>{esc(row['user_id'])}</code></td>"
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
    approval = ""
    if is_owner(current_user):
        pending = db_rows("SELECT username, created_at FROM dashboard_users WHERE status='pending' ORDER BY created_at")
        rows = "".join(
            f"<tr><td>{esc(row['username'])}</td><td>{datetime.fromtimestamp(row['created_at']).strftime('%d.%m.%Y %H:%M')}</td>"
            f"<td><form method='post' action='/approve'><input type='hidden' name='username' value='{esc(row['username'])}'><button>Одобрить</button></form></td></tr>"
            for row in pending
        )
        approval = f"<h2>Заявки на доступ</h2><div class='table-wrap'><table><tr><th>Логин</th><th>Дата</th><th></th></tr>{rows or '<tr><td colspan=3>Новых заявок нет</td></tr>'}</table></div>"
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta http-equiv="refresh" content="30">
<title>Podslushka DB</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#0f172a;color:#dbeafe;font:14px Segoe UI,Arial,sans-serif}}
main{{max-width:1400px;margin:auto;padding:28px}}h1{{margin:0 0 6px;font-size:28px}}h2{{margin-top:34px}}
.muted{{color:#94a3b8}}.cards{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:24px 0}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px}}
.card b{{display:block;color:#94a3b8;font-size:12px}}.card strong{{display:block;font-size:27px;margin-top:8px}}
.toolbar{{display:flex;gap:10px;flex-wrap:wrap;margin:22px 0}}input,select{{background:#1e293b;color:#e2e8f0;border:1px solid #475569;border-radius:8px;padding:10px 12px;min-width:220px}}
.table-wrap{{overflow:auto;background:#1e293b;border:1px solid #334155;border-radius:12px}}
table{{border-collapse:collapse;width:100%;min-width:850px}}th,td{{padding:11px 13px;text-align:left;border-bottom:1px solid #334155}}
th{{color:#93c5fd;background:#172033;position:sticky;top:0}}tr:hover{{background:#263449}}
code{{color:#a7f3d0}}.status{{padding:3px 8px;border-radius:10px;background:#334155}}
button{{background:#2563eb;color:white;border:0;border-radius:8px;padding:9px 14px;cursor:pointer}}
.danger{{background:#b91c1c}}.empty{{display:none;color:#94a3b8;padding:14px}}
@media(max-width:900px){{.cards{{grid-template-columns:repeat(3,1fr)}}}}
</style></head><body><main>
<h1>Podslushka · база данных</h1><div class="muted">Только этот компьютер · автообновление каждые 30 секунд</div>
<div class="cards">{cards}</div>
<div class="toolbar">
<input id="search" placeholder="Поиск: имя, username, ID, текст..." autocomplete="off">
<select id="status"><option value="">Все статусы</option><option value="pending">На модерации</option><option value="published">Опубликовано</option><option value="rejected">Отклонено</option><option value="deleted">Удалено</option></select>
<button onclick="location.reload()">Обновить сейчас</button>
<a href="/backup"><button>Резервная копия</button></a>
<a href="/logout"><button class="danger">Выйти</button></a>
</div>
<h2>Пользователи <span class="muted" id="user-count"></span></h2><div class="table-wrap"><table><tr><th>ID</th><th>Имя</th><th>Username</th><th>Язык</th><th>Заявок</th><th>Последний контакт</th></tr>{user_rows}</table><div class="empty" id="users-empty">Ничего не найдено</div></div>
<h2>Последние заявки <span class="muted" id="post-count"></span></h2><div class="table-wrap"><table><tr><th>ID</th><th>User ID</th><th>Автор</th><th>Тип</th><th>Статус</th><th>Текст</th></tr>{post_rows}</table><div class="empty" id="posts-empty">Ничего не найдено</div></div>
{approval}
<script>
const search = document.getElementById('search');
const status = document.getElementById('status');
function filterRows() {{
  const q = search.value.toLowerCase().trim();
  const selected = status.value;
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
search.addEventListener('input', filterRows);
status.addEventListener('change', filterRows);
filterRows();
</script>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/logout":
            token = next((item.split("=", 1)[1] for item in self.headers.get("Cookie", "").split("; ")
                          if item.startswith("session=")), None)
            if token:
                SESSIONS.pop(token, None)
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "session=; Max-Age=0; HttpOnly; SameSite=Strict")
            self.end_headers()
            return
        if not auth_user(self):
            body = auth_page().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/":
            body = page(auth_user(self) or "").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        elif path == "/backup":
            backup = ROOT / "backups"
            backup.mkdir(exist_ok=True)
            target = backup / f"podslushka_{datetime.now():%Y%m%d_%H%M%S}.db"
            shutil.copy2(DB_PATH, target)
            body = f"Резервная копия создана: {target.name}".encode("utf-8")
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
        fields = parse_qs(self.rfile.read(length).decode("utf-8"))
        username = fields.get("username", [""])[0].strip()
        password = fields.get("password", [""])[0]
        error = ""
        if path == "/register":
            if len(username) < 3 or len(password) < 8:
                error = "Логин от 3 символов, пароль минимум 8 символов."
            else:
                try:
                    with sqlite3.connect(DB_PATH) as conn:
                        conn.execute(
                            "INSERT INTO dashboard_users (username, password_hash, status, created_at) VALUES (?, ?, 'pending', ?)",
                            (username, password_hash(password), int(datetime.now().timestamp())),
                        )
                        conn.commit()
                except sqlite3.IntegrityError:
                    error = "Такой логин уже зарегистрирован."
            if not error:
                body = auth_page("Заявка отправлена. Владелец должен одобрить доступ перед входом.").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        elif path == "/approve":
            if not is_owner(auth_user(self)):
                self.send_error(403)
                return
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("UPDATE dashboard_users SET status='approved' WHERE username=?", (username,))
                conn.commit()
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        elif path == "/login":
            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute(
                    "SELECT password_hash, status FROM dashboard_users WHERE username = ?", (username,)
                ).fetchone()
            owner_login = (
                username == OWNER_USERNAME and OWNER_PASSWORD
                and secrets.compare_digest(password, OWNER_PASSWORD)
            )
            if not owner_login and (not row or row[1] != "approved" or not verify_password(password, row[0])):
                error = "Неверный логин, пароль или доступ ещё не одобрен владельцем."
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
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = username
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"session={token}; HttpOnly; SameSite=Strict")
        self.end_headers()

    def log_message(self, *_):
        return


if __name__ == "__main__":
    init_auth()
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

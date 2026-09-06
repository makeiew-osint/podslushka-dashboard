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
                role TEXT NOT NULL DEFAULT 'user',
                created_at INTEGER NOT NULL
            )
        """)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(dashboard_users)")}
        if "status" not in columns:
            conn.execute("ALTER TABLE dashboard_users ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
        if "role" not in columns:
            conn.execute("ALTER TABLE dashboard_users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        conn.execute("""CREATE TABLE IF NOT EXISTS dashboard_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            created_at INTEGER NOT NULL
        )""")
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
    if not username:
        return False
    if OWNER_USERNAME and username == OWNER_USERNAME:
        return True
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT role, status FROM dashboard_users WHERE username=?", (username,)
        ).fetchone()
    return bool(row and row[0] == "owner" and row[1] == "approved")


def log_action(actor: str, action: str, target: str = "") -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO dashboard_actions (actor, action, target, created_at) VALUES (?, ?, ?, ?)",
            (actor, action, target, int(datetime.now().timestamp())),
        )
        conn.commit()


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
            f"<td><form class='inline' method='post' action='/approve'><input type='hidden' name='username' value='{esc(row['username'])}'><button>Одобрить</button></form>"
            f"<form class='inline' method='post' action='/reject'><input type='hidden' name='username' value='{esc(row['username'])}'><button class='danger'>Отклонить</button></form></td></tr>"
            for row in pending
        )
        owners = db_rows("SELECT username, created_at FROM dashboard_users WHERE role='owner' AND status='approved' ORDER BY username")
        owner_rows = "".join(
            f"<tr><td>{esc(row['username'])}</td><td>{datetime.fromtimestamp(row['created_at']).strftime('%d.%m.%Y %H:%M')}</td></tr>"
            for row in owners
        )
        actions = db_rows("SELECT actor, action, target, created_at FROM dashboard_actions ORDER BY created_at DESC LIMIT 100")
        action_rows = "".join(
            f"<tr><td>{datetime.fromtimestamp(row['created_at']).strftime('%d.%m.%Y %H:%M:%S')}</td><td>{esc(row['actor'])}</td><td>{esc(row['action'])}</td><td>{esc(row['target'])}</td></tr>"
            for row in actions
        )
        approval = f"""
<section id="access"><h2>Заявки на доступ</h2><div class="table-wrap"><table><tr><th>Логин</th><th>Дата</th><th>Действие</th></tr>{rows or '<tr><td colspan=3>Новых заявок нет</td></tr>'}</table></div></section>
<section id="owners"><h2>Владельцы</h2><form class="owner-form" method="post" action="/add-owner"><input name="username" placeholder="Логин нового владельца" required minlength="3"><input name="password" type="password" placeholder="Пароль нового владельца" required minlength="8"><button>Добавить владельца</button></form><div class="table-wrap"><table><tr><th>Логин</th><th>Добавлен</th></tr>{owner_rows or '<tr><td colspan=2>Дополнительных владельцев нет</td></tr>'}</table></div></section>
<section id="actions"><h2>Действия администраторов</h2><div class="table-wrap"><table><tr><th>Время</th><th>Администратор</th><th>Действие</th><th>Объект</th></tr>{action_rows or '<tr><td colspan=4>Действий пока нет</td></tr>'}</table></div></section>"""
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta http-equiv="refresh" content="30">
<title>Podslushka DB</title><style>
:root{{--bg:#0b1220;--sidebar:#111c2e;--panel:#162238;--panel2:#1b2940;--line:#2b405f;--text:#edf5ff;--muted:#91a4bf;--blue:#4f8cff;--blue2:#6ca0ff;--danger:#d14d5a}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:radial-gradient(circle at 80% 0,#1b376022,transparent 36%),var(--bg);color:var(--text);font:14px Inter,Segoe UI,Arial,sans-serif}}
.layout{{display:flex;min-height:100vh}}.sidebar{{position:fixed;inset:0 auto 0 0;width:255px;padding:25px 16px;background:linear-gradient(180deg,#13213a,#0e1728);border-right:1px solid #243956;z-index:5}}
.brand{{display:flex;align-items:center;gap:11px;padding:4px 10px 28px;font-size:19px;font-weight:800;letter-spacing:-.4px}}.logo{{display:grid;place-items:center;width:36px;height:36px;border-radius:11px;background:linear-gradient(135deg,#70a7ff,#3d6cf0);box-shadow:0 8px 22px #3975ed55;font-size:19px}}
.menu-title{{padding:0 11px 9px;color:#7085a3;text-transform:uppercase;font-size:10px;font-weight:800;letter-spacing:1px}}.nav{{display:grid;gap:5px}}.nav a{{display:flex;align-items:center;gap:11px;padding:12px 11px;border:1px solid transparent;border-radius:10px;color:#adc0d9;text-decoration:none;font-weight:600;transition:.18s}}.nav a:hover,.nav a.active{{color:#fff;background:#263e63;border-color:#3b6095;box-shadow:0 6px 18px #06112655}}.nav .icon{{width:20px;text-align:center;font-size:16px}}
.sidebar-footer{{position:absolute;bottom:22px;left:25px;right:25px;color:#6f85a3;font-size:11px;line-height:1.55}}.content{{width:100%;margin-left:255px;padding:34px clamp(22px,4vw,58px) 60px}}.topbar{{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;margin-bottom:25px}}h1{{margin:0 0 7px;font-size:30px;letter-spacing:-.8px}}h2{{margin:42px 0 15px;font-size:21px;letter-spacing:-.3px}}.muted{{color:var(--muted)}}
.cards{{display:grid;grid-template-columns:repeat(6,1fr);gap:13px;margin:0 0 27px}}.card{{background:linear-gradient(145deg,#1b2b45,#152238);border:1px solid #2b4568;border-radius:15px;padding:17px;box-shadow:0 12px 30px #03091435}}.card b{{display:block;color:#94aaca;font-size:12px;font-weight:600}}.card strong{{display:block;font-size:28px;margin-top:9px;color:#f4f8ff}}
.toolbar{{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 25px;padding:15px;background:#111d30;border:1px solid #253b5b;border-radius:14px;box-shadow:0 10px 28px #03091435}}input,select{{background:#0e192b;color:#e2e8f0;border:1px solid #3a5272;border-radius:9px;padding:11px 13px;min-width:220px;outline:none}}input:focus,select:focus{{border-color:var(--blue);box-shadow:0 0 0 3px #4f8cff22}}button{{background:linear-gradient(135deg,var(--blue),#3e6fe8);color:white;border:0;border-radius:9px;padding:10px 15px;font-weight:700;cursor:pointer;transition:.18s}}button:hover{{filter:brightness(1.1);transform:translateY(-1px)}}.danger{{background:linear-gradient(135deg,#c84d5a,#a83240)}}
.table-wrap{{overflow:auto;background:linear-gradient(145deg,#1b2940,#172438);border:1px solid #2d4565;border-radius:14px;box-shadow:0 12px 30px #03091435}}table{{border-collapse:collapse;width:100%;min-width:850px}}th,td{{padding:13px 14px;text-align:left;border-bottom:1px solid #2b405f}}th{{color:#8fc0ff;background:#18263b;position:sticky;top:0;font-size:12px;text-transform:uppercase;letter-spacing:.3px}}tr:last-child td{{border-bottom:0}}tr:hover{{background:#243650}}code{{color:#a7f3d0}}.status{{padding:4px 9px;border-radius:20px;background:#304664;color:#d7e8ff;font-size:12px}}
.empty{{display:none;color:#94a3b8;padding:16px}}.inline{{display:inline}}.inline button{{margin:2px 4px 2px 0}}.owner-form{{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 16px}}.owner-form input{{min-width:220px}}section{{scroll-margin-top:20px}}
@media(max-width:1150px){{.cards{{grid-template-columns:repeat(3,1fr)}}}}@media(max-width:700px){{.sidebar{{position:relative;width:100%;padding:16px;min-height:0;border-right:0;border-bottom:1px solid #243956}}.layout{{display:block}}.content{{margin-left:0;padding:25px 16px 45px}}.sidebar-footer{{display:none}}.brand{{padding-bottom:17px}}.nav{{grid-template-columns:repeat(2,1fr)}}.nav a{{padding:10px;font-size:12px}}.topbar{{display:block}}.cards{{grid-template-columns:repeat(2,1fr);gap:9px}}.card{{padding:13px}}.card strong{{font-size:23px}}h1{{font-size:25px}}}}
</style></head><body><div class="layout">
<aside class="sidebar"><div class="brand"><span class="logo">◈</span><span>Podslushka DB</span></div><div class="menu-title">Навигация</div><nav class="nav">
<a class="active" href="#overview"><span class="icon">⌂</span>Обзор</a><a href="#users"><span class="icon">♙</span>Пользователи</a><a href="#posts"><span class="icon">▤</span>Заявки</a>
{('<a href="#access"><span class="icon">✓</span>Доступ</a><a href="#actions"><span class="icon">◷</span>Журнал действий</a><a href="#owners"><span class="icon">♛</span>Владельцы</a>' if is_owner(current_user) else '')}
</nav><div class="sidebar-footer">Защищённая панель управления<br>Автообновление каждые 30 секунд</div></aside>
<main class="content"><div class="topbar"><div><h1>Панель управления</h1><div class="muted">Мониторинг базы данных и модерации</div></div><a href="/logout"><button class="danger">Выйти</button></a></div>
<section id="overview"><div class="cards">{cards}</div></section>
<div class="toolbar">
<input id="search" placeholder="Поиск: имя, username, ID, текст..." autocomplete="off">
<select id="status"><option value="">Все статусы</option><option value="pending">На модерации</option><option value="published">Опубликовано</option><option value="rejected">Отклонено</option><option value="deleted">Удалено</option></select>
<button onclick="location.reload()">↻ Обновить</button><a href="/backup"><button>↓ Резервная копия</button></a>
</div>
<section id="users"><h2>Пользователи <span class="muted" id="user-count"></span></h2><div class="table-wrap"><table><tr><th>ID</th><th>Имя</th><th>Username</th><th>Язык</th><th>Заявок</th><th>Последний контакт</th></tr>{user_rows}</table><div class="empty" id="users-empty">Ничего не найдено</div></div></section>
<section id="posts"><h2>Последние заявки <span class="muted" id="post-count"></span></h2><div class="table-wrap"><table><tr><th>ID</th><th>User ID</th><th>Автор</th><th>Тип</th><th>Статус</th><th>Текст</th></tr>{post_rows}</table><div class="empty" id="posts-empty">Ничего не найдено</div></div></section>
{approval}
</main></div><script>
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
</body></html>"""


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
            log_action(auth_user(self) or "owner", "Одобрил доступ", username)
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        elif path == "/reject":
            if not is_owner(auth_user(self)):
                self.send_error(403)
                return
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("UPDATE dashboard_users SET status='rejected' WHERE username=?", (username,))
                conn.commit()
            log_action(auth_user(self) or "owner", "Отклонил доступ", username)
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        elif path == "/add-owner":
            actor = auth_user(self)
            if not is_owner(actor):
                self.send_error(403)
                return
            if len(username) < 3 or len(password) < 8:
                error = "Логин владельца от 3 символов, пароль минимум 8 символов."
            else:
                try:
                    with sqlite3.connect(DB_PATH) as conn:
                        conn.execute(
                            "INSERT INTO dashboard_users (username, password_hash, status, role, created_at) VALUES (?, ?, 'approved', 'owner', ?)",
                            (username, password_hash(password), int(datetime.now().timestamp())),
                        )
                        conn.commit()
                    log_action(actor or "owner", "Добавил владельца", username)
                except sqlite3.IntegrityError:
                    error = "Такой логин уже существует."
            if not error:
                self.send_response(302)
                self.send_header("Location", "/#owners")
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
        if owner_login:
            log_action(username, "Вошёл как владелец", "")
        else:
            log_action(username, "Вошёл в панель", "")
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

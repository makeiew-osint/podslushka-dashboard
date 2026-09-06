from __future__ import annotations

import aiosqlite
import hashlib
import time
from typing import Optional, Any


class Database:
    def __init__(self, path: str = "podslushka.db"):
        self.path = path
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self):
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._create_tables()

    async def close(self):
        if self._conn:
            await self._conn.close()

    async def _execute(self, sql: str, params: tuple = ()) -> aiosqlite.Cursor:
        if not self._conn:
            raise RuntimeError("DB not connected")
        return await self._conn.execute(sql, params)

    async def _commit(self):
        if self._conn:
            await self._conn.commit()

    async def _create_tables(self):
        tables = [
            """CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                first_name TEXT, last_name TEXT, username TEXT,
                language_code TEXT, is_premium INTEGER DEFAULT 0,
                ui_lang TEXT,
                first_seen INTEGER, last_seen INTEGER
            )""",
            """CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                text TEXT,
                file_id TEXT,
                media_group_id TEXT,
                status TEXT DEFAULT 'pending',
                public_id INTEGER,
                reject_reason TEXT,
                moderated_by INTEGER,
                created_at INTEGER,
                moderated_at INTEGER,
                scheduled_at INTEGER,
                hash TEXT,
                channel_message_id INTEGER,
                is_pinned INTEGER DEFAULT 0
            )""",
            """CREATE TABLE IF NOT EXISTS media_group_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                file_id TEXT NOT NULL,
                caption TEXT,
                FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
            )""",
            """CREATE TABLE IF NOT EXISTS bans (
                user_id INTEGER PRIMARY KEY,
                reason TEXT,
                created_at INTEGER
            )""",
            """CREATE TABLE IF NOT EXISTS warns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                reason TEXT,
                post_id INTEGER,
                admin_id INTEGER,
                created_at INTEGER
            )""",
            """CREATE TABLE IF NOT EXISTS banned_words (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                word TEXT NOT NULL UNIQUE,
                created_at INTEGER
            )""",
            """CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                post_id INTEGER,
                details TEXT,
                created_at INTEGER
            )""",
            """CREATE TABLE IF NOT EXISTS votes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                vote INTEGER NOT NULL,
                created_at INTEGER,
                UNIQUE(public_id, user_id)
            )""",
            """CREATE TABLE IF NOT EXISTS scheduled_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                scheduled_at INTEGER NOT NULL,
                created_at INTEGER
            )""",
            """CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id INTEGER NOT NULL,
                reporter_id INTEGER NOT NULL,
                reason TEXT,
                created_at INTEGER
            )""",
            """CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                text TEXT NOT NULL,
                created_at INTEGER
            )""",
            """CREATE TABLE IF NOT EXISTS post_edits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                old_text TEXT,
                new_text TEXT NOT NULL,
                created_at INTEGER
            )""",
            """CREATE TABLE IF NOT EXISTS top_weekly (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                week_start INTEGER NOT NULL,
                post_id INTEGER NOT NULL,
                public_id INTEGER NOT NULL,
                votes_up INTEGER DEFAULT 0,
                created_at INTEGER
            )""",
        ]
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_posts_status ON posts(status);",
            "CREATE INDEX IF NOT EXISTS idx_posts_hash ON posts(hash);",
            "CREATE INDEX IF NOT EXISTS idx_posts_media_group ON posts(media_group_id);",
            "CREATE INDEX IF NOT EXISTS idx_media_group_post ON media_group_items(post_id);",
            "CREATE INDEX IF NOT EXISTS idx_warns_user ON warns(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_reports_public ON reports(public_id);",
            "CREATE INDEX IF NOT EXISTS idx_comments_public ON comments(public_id);",
        ]
        for sql in tables + indexes:
            await self._execute(sql)
        await self._migrate_columns()
        await self._commit()

    async def _migrate_columns(self):
        migrations = {
            "posts": {
                "file_id": "TEXT",
                "media_group_id": "TEXT",
                "reject_reason": "TEXT",
                "moderated_by": "INTEGER",
                "moderated_at": "INTEGER",
                "scheduled_at": "INTEGER",
                "hash": "TEXT",
                "channel_message_id": "INTEGER",
                "is_pinned": "INTEGER DEFAULT 0",
            },
            "users": {
                "ui_lang": "TEXT",
            },
        }
        for table, columns in migrations.items():
            cursor = await self._execute(f"PRAGMA table_info({table})")
            existing = {row[1] for row in await cursor.fetchall()}
            for name, definition in columns.items():
                if name not in existing:
                    await self._execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {definition}"
                    )

    # ── Users ──
    async def upsert_user(self, user_id: int, first_name: str | None, last_name: str | None,
                          username: str | None, language_code: str | None, is_premium: bool):
        now = int(time.time())
        await self._execute("""
            INSERT INTO users (user_id, first_name, last_name, username, language_code, is_premium, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                first_name=excluded.first_name, last_name=excluded.last_name,
                username=excluded.username, language_code=excluded.language_code,
                is_premium=excluded.is_premium, last_seen=excluded.last_seen
        """, (user_id, first_name, last_name, username, language_code, int(is_premium), now, now))
        await self._commit()

    async def get_user(self, user_id: int) -> Optional[aiosqlite.Row]:
        cur = await self._execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        return await cur.fetchone()

    async def set_ui_lang(self, user_id: int, lang: str):
        await self._execute("UPDATE users SET ui_lang = ? WHERE user_id = ?", (lang, user_id))
        await self._commit()

    async def get_ui_lang(self, user_id: int) -> Optional[str]:
        cur = await self._execute("SELECT ui_lang FROM users WHERE user_id = ?", (user_id,))
        row = await cur.fetchone()
        return row["ui_lang"] if row else None

    # ── Bans ──
    async def ban(self, user_id: int, reason: str = ""):
        now = int(time.time())
        await self._execute("INSERT OR REPLACE INTO bans (user_id, reason, created_at) VALUES (?, ?, ?)",
                            (user_id, reason, now))
        await self._commit()

    async def unban(self, user_id: int) -> bool:
        cur = await self._execute("DELETE FROM bans WHERE user_id = ?", (user_id,))
        await self._commit()
        return cur.rowcount > 0

    async def is_banned(self, user_id: int) -> bool:
        cur = await self._execute("SELECT 1 FROM bans WHERE user_id = ?", (user_id,))
        return await cur.fetchone() is not None

    async def list_bans(self) -> list[aiosqlite.Row]:
        cur = await self._execute("""
            SELECT b.*, u.first_name, u.username FROM bans b
            LEFT JOIN users u ON b.user_id = u.user_id
            ORDER BY b.created_at DESC
        """)
        return await cur.fetchall()

    # ── Warns ──
    async def add_warn(self, user_id: int, reason: str = "", post_id: int | None = None, admin_id: int | None = None):
        now = int(time.time())
        await self._execute("""
            INSERT INTO warns (user_id, reason, post_id, admin_id, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, reason, post_id, admin_id, now))
        await self._commit()

    async def count_warns(self, user_id: int) -> int:
        cur = await self._execute("SELECT COUNT(*) as cnt FROM warns WHERE user_id = ?", (user_id,))
        row = await cur.fetchone()
        return row["cnt"] if row else 0

    async def get_warns(self, user_id: int) -> list[aiosqlite.Row]:
        cur = await self._execute("""
            SELECT * FROM warns WHERE user_id = ? ORDER BY created_at DESC
        """, (user_id,))
        return await cur.fetchall()

    async def clear_warns(self, user_id: int):
        await self._execute("DELETE FROM warns WHERE user_id = ?", (user_id,))
        await self._commit()

    # ── Banned words ──
    async def add_banned_word(self, word: str):
        now = int(time.time())
        try:
            await self._execute("INSERT INTO banned_words (word, created_at) VALUES (?, ?)", (word.lower(), now))
            await self._commit()
            return True
        except Exception:
            return False

    async def remove_banned_word(self, word: str):
        await self._execute("DELETE FROM banned_words WHERE word = ?", (word.lower(),))
        await self._commit()

    async def list_banned_words(self) -> list[str]:
        cur = await self._execute("SELECT word FROM banned_words ORDER BY word")
        rows = await cur.fetchall()
        return [r["word"] for r in rows]

    async def check_banned_words(self, text: str | None) -> list[str]:
        if not text:
            return []
        words = await self.list_banned_words()
        found = []
        lower = text.lower()
        for w in words:
            if w in lower:
                found.append(w)
        return found

    # ── Posts ──
    async def add_post(self, user_id: int, kind: str, text: str | None, file_id: str | None,
                       media_group_id: str | None = None, user_name: str | None = None,
                       username: str | None = None) -> int:
        now = int(time.time())
        content = (text or "") + (file_id or "")
        h = hashlib.md5(content.encode()).hexdigest()
        cur = await self._execute("""
            INSERT INTO posts (user_id, kind, text, file_id, media_group_id, created_at, hash, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
        """, (user_id, kind, text, file_id, media_group_id, now, h))
        await self._commit()
        return cur.lastrowid

    async def add_media_group_item(self, post_id: int, kind: str, file_id: str, caption: str | None = None):
        await self._execute("""
            INSERT INTO media_group_items (post_id, kind, file_id, caption)
            VALUES (?, ?, ?, ?)
        """, (post_id, kind, file_id, caption))
        await self._commit()

    async def get_media_group_items(self, post_id: int) -> list[aiosqlite.Row]:
        cur = await self._execute("""
            SELECT * FROM media_group_items WHERE post_id = ? ORDER BY id
        """, (post_id,))
        return await cur.fetchall()

    async def get_post(self, post_id: int) -> Optional[aiosqlite.Row]:
        cur = await self._execute("SELECT * FROM posts WHERE id = ?", (post_id,))
        return await cur.fetchone()

    async def get_post_by_public(self, public_id: int) -> Optional[aiosqlite.Row]:
        cur = await self._execute("SELECT * FROM posts WHERE public_id = ?", (public_id,))
        return await cur.fetchone()

    async def list_pending(self) -> list[aiosqlite.Row]:
        cur = await self._execute("""
            SELECT p.*, u.first_name as user_name, u.username
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.user_id
            WHERE p.status = 'pending'
            ORDER BY p.created_at
        """)
        return await cur.fetchall()

    async def approve(self, post_id: int) -> int:
        now = int(time.time())
        cur = await self._execute("SELECT MAX(public_id) as max_id FROM posts")
        row = await cur.fetchone()
        public_id = (row["max_id"] or 0) + 1
        await self._execute("""
            UPDATE posts SET status='published', public_id=?, moderated_at=?
            WHERE id=?
        """, (public_id, now, post_id))
        await self._commit()
        return public_id

    async def reject(self, post_id: int, reason: str | None = None, admin_id: int | None = None):
        now = int(time.time())
        await self._execute("""
            UPDATE posts SET status='rejected', reject_reason=?, moderated_by=?, moderated_at=?
            WHERE id=?
        """, (reason, admin_id, now, post_id))
        await self._commit()

    async def set_channel_message_id(self, post_id: int, message_id: int):
        await self._execute("UPDATE posts SET channel_message_id = ? WHERE id = ?", (message_id, post_id))
        await self._commit()

    async def set_pinned(self, post_id: int, pinned: bool = True):
        await self._execute("UPDATE posts SET is_pinned = ? WHERE id = ?", (1 if pinned else 0, post_id))
        await self._commit()

    async def delete_post(self, post_id: int):
        await self._execute("UPDATE posts SET status='deleted' WHERE id = ?", (post_id,))
        await self._commit()

    async def edit_post_text(self, post_id: int, new_text: str):
        now = int(time.time())
        old = await self.get_post(post_id)
        old_text = old["text"] if old else None
        await self._execute("UPDATE posts SET text = ? WHERE id = ?", (new_text, post_id))
        await self._execute("""
            INSERT INTO post_edits (post_id, old_text, new_text, created_at)
            VALUES (?, ?, ?, ?)
        """, (post_id, old_text, new_text, now))
        await self._commit()

    async def last_post_time(self, user_id: int) -> Optional[int]:
        cur = await self._execute("""
            SELECT created_at FROM posts WHERE user_id = ? ORDER BY created_at DESC LIMIT 1
        """, (user_id,))
        row = await cur.fetchone()
        return row["created_at"] if row else None

    async def user_posts(self, user_id: int, limit: int = 10) -> list[aiosqlite.Row]:
        cur = await self._execute("""
            SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC LIMIT ?
        """, (user_id, limit))
        return await cur.fetchall()

    async def user_post_counts(self, user_id: int) -> dict[str, int]:
        cur = await self._execute("""
            SELECT status, COUNT(*) as cnt FROM posts WHERE user_id = ? GROUP BY status
        """, (user_id,))
        rows = await cur.fetchall()
        counts = {"total": 0, "pending": 0, "published": 0, "rejected": 0}
        for r in rows:
            counts[r["status"]] = r["cnt"]
            counts["total"] += r["cnt"]
        return counts

    async def user_activity_counts(self, user_id: int) -> dict[str, int]:
        cur = await self._execute("""
            SELECT
                (SELECT COUNT(*) FROM comments WHERE user_id = ?) AS comments,
                (SELECT COUNT(*) FROM reports WHERE reporter_id = ?) AS reports,
                (SELECT COUNT(*) FROM votes WHERE user_id = ?) AS votes,
                (SELECT COUNT(*) FROM warns WHERE user_id = ?) AS warns
        """, (user_id, user_id, user_id, user_id))
        row = await cur.fetchone()
        return {key: row[key] or 0 for key in ("comments", "reports", "votes", "warns")}

    async def posts_last_hour(self, user_id: int) -> int:
        since = int(time.time()) - 3600
        cur = await self._execute("""
            SELECT COUNT(*) as cnt FROM posts WHERE user_id = ? AND created_at > ?
        """, (user_id, since))
        row = await cur.fetchone()
        return row["cnt"] if row else 0

    async def find_duplicate(self, user_id: int, text: str | None, file_id: str | None) -> Optional[aiosqlite.Row]:
        since = int(time.time()) - 600
        content = (text or "") + (file_id or "")
        h = hashlib.md5(content.encode()).hexdigest()
        cur = await self._execute("""
            SELECT * FROM posts WHERE user_id = ? AND hash = ? AND created_at > ? LIMIT 1
        """, (user_id, h, since))
        return await cur.fetchone()

    async def search_posts(self, query: str, limit: int = 20) -> list[aiosqlite.Row]:
        q = f"%{query}%"
        cur = await self._execute("""
            SELECT p.*, u.first_name, u.username FROM posts p
            LEFT JOIN users u ON p.user_id = u.user_id
            WHERE p.text LIKE ? OR p.file_id LIKE ?
            ORDER BY p.created_at DESC LIMIT ?
        """, (q, q, limit))
        return await cur.fetchall()

    async def get_top_posts_week(self, limit: int = 5) -> list[aiosqlite.Row]:
        week_ago = int(time.time()) - 7 * 86400
        cur = await self._execute("""
            SELECT p.*, COUNT(CASE WHEN v.vote = 1 THEN 1 END) as upvotes
            FROM posts p
            LEFT JOIN votes v ON p.public_id = v.public_id
            WHERE p.status = 'published' AND p.created_at > ?
            GROUP BY p.id
            ORDER BY upvotes DESC, p.created_at DESC
            LIMIT ?
        """, (week_ago, limit))
        return await cur.fetchall()

    # ── Stats ──
    async def stats(self) -> dict[str, Any]:
        cur = await self._execute("""
            SELECT 
                SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN status='published' THEN 1 ELSE 0 END) as published,
                SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) as rejected,
                SUM(CASE WHEN status='deleted' THEN 1 ELSE 0 END) as deleted,
                COUNT(DISTINCT user_id) as authors,
                (SELECT COUNT(*) FROM users) as users,
                (SELECT COUNT(*) FROM bans) as bans,
                (SELECT COUNT(*) FROM warns) as warns,
                (SELECT COUNT(*) FROM reports) as reports,
                MAX(public_id) as last_public_id
            FROM posts
        """)
        row = await cur.fetchone()
        return {
            "pending": row["pending"] or 0,
            "published": row["published"] or 0,
            "rejected": row["rejected"] or 0,
            "deleted": row["deleted"] or 0,
            "authors": row["authors"] or 0,
            "users": row["users"] or 0,
            "bans": row["bans"] or 0,
            "warns": row["warns"] or 0,
            "reports": row["reports"] or 0,
            "last_public_id": row["last_public_id"] or 0,
        }

    # ── Admin logs ──
    async def log_admin_action(self, admin_id: int, action: str, post_id: int | None = None, details: str | None = None):
        now = int(time.time())
        await self._execute("""
            INSERT INTO admin_logs (admin_id, action, post_id, details, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (admin_id, action, post_id, details, now))
        await self._commit()

    async def get_admin_logs(self, post_id: int) -> list[aiosqlite.Row]:
        cur = await self._execute("""
            SELECT * FROM admin_logs WHERE post_id = ? ORDER BY created_at DESC
        """, (post_id,))
        return await cur.fetchall()

    # ── Votes ──
    async def add_vote(self, public_id: int, user_id: int, vote: int) -> bool:
        now = int(time.time())
        try:
            await self._execute("""
                INSERT INTO votes (public_id, user_id, vote, created_at)
                VALUES (?, ?, ?, ?)
            """, (public_id, user_id, vote, now))
            await self._commit()
            return True
        except Exception:
            return False

    async def get_votes(self, public_id: int) -> dict[str, int]:
        cur = await self._execute("""
            SELECT vote, COUNT(*) as cnt FROM votes WHERE public_id = ? GROUP BY vote
        """, (public_id,))
        rows = await cur.fetchall()
        return {str(r["vote"]): r["cnt"] for r in rows}

    # ── Scheduled ──
    async def add_scheduled(self, post_id: int, scheduled_at: int):
        now = int(time.time())
        await self._execute("""
            INSERT INTO scheduled_posts (post_id, scheduled_at, created_at)
            VALUES (?, ?, ?)
        """, (post_id, scheduled_at, now))
        await self._commit()

    async def get_due_scheduled(self) -> list[aiosqlite.Row]:
        now = int(time.time())
        cur = await self._execute("""
            SELECT s.*, p.* FROM scheduled_posts s
            JOIN posts p ON s.post_id = p.id
            WHERE s.scheduled_at <= ? AND p.status = 'pending'
        """, (now,))
        return await cur.fetchall()

    async def remove_scheduled(self, post_id: int):
        await self._execute("DELETE FROM scheduled_posts WHERE post_id = ?", (post_id,))
        await self._commit()

    # ── Reports ──
    async def add_report(self, public_id: int, reporter_id: int, reason: str | None = None):
        now = int(time.time())
        await self._execute("""
            INSERT INTO reports (public_id, reporter_id, reason, created_at)
            VALUES (?, ?, ?, ?)
        """, (public_id, reporter_id, reason, now))
        await self._commit()

    async def get_reports(self, public_id: int) -> list[aiosqlite.Row]:
        cur = await self._execute("""
            SELECT r.*, u.first_name, u.username FROM reports r
            LEFT JOIN users u ON r.reporter_id = u.user_id
            WHERE r.public_id = ? ORDER BY r.created_at DESC
        """, (public_id,))
        return await cur.fetchall()

    async def count_reports(self, public_id: int) -> int:
        cur = await self._execute("SELECT COUNT(*) as cnt FROM reports WHERE public_id = ?", (public_id,))
        row = await cur.fetchone()
        return row["cnt"] if row else 0

    # ── Comments ──
    async def add_comment(self, public_id: int, user_id: int, text: str):
        now = int(time.time())
        await self._execute("""
            INSERT INTO comments (public_id, user_id, text, created_at)
            VALUES (?, ?, ?, ?)
        """, (public_id, user_id, text, now))
        await self._commit()

    async def get_comments(self, public_id: int) -> list[aiosqlite.Row]:
        cur = await self._execute("""
            SELECT c.*, u.first_name, u.username FROM comments c
            LEFT JOIN users u ON c.user_id = u.user_id
            WHERE c.public_id = ? ORDER BY c.created_at
        """, (public_id,))
        return await cur.fetchall()

    # ── Post edits ──
    async def get_post_edits(self, post_id: int) -> list[aiosqlite.Row]:
        cur = await self._execute("""
            SELECT * FROM post_edits WHERE post_id = ? ORDER BY created_at DESC
        """, (post_id,))
        return await cur.fetchall()

import asyncio
import html
import json
import logging
import os
import time
import urllib.request
from datetime import datetime
from typing import Optional, Dict, List, Any

from aiogram import Bot, Dispatcher, F
from aiogram.types import (
    Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton,
    InputMediaPhoto, InputMediaVideo, InputMediaAudio, InputMediaDocument,
)
from aiogram.filters import Command, CommandObject
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

from config import load_settings
from db import Database
from i18n import t

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

cfg = load_settings()
db = Database(cfg.db_path, cfg.database_url)

bot = Bot(token=cfg.bot_token)
storage = MemoryStorage()
dp = Dispatcher(storage=storage)

def _esc(text: Any) -> str:
    if text is None:
        return "—"
    return html.escape(str(text))


def _yn(value: Any) -> str:
    return "✅ Да" if value else "❌ Нет"


def _ts(dt: Optional[datetime]) -> str:
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


async def _lang(user_id: int) -> str:
    l = await db.get_ui_lang(user_id)
    return l or "ru"


async def _audit(actor: Any, action: str, target: Any = ""):
    try:
        await db.log_dashboard_action(str(actor), action, str(target))
    except Exception:
        logging.exception("Dashboard action audit failed")


class UserState(StatesGroup):
    preview = State()
    editing = State()
    commenting = State()
    reporting = State()


class AdminState(StatesGroup):
    ban_reason = State()
    reject_reason = State()
    broadcast = State()


def _lang_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🇷🇺 Русский", callback_data="lang:ru")],
        [InlineKeyboardButton(text="🇬🇧 English", callback_data="lang:en")],
        [InlineKeyboardButton(text="🇺🇦 Українська", callback_data="lang:uk")],
    ])


def _preview_kb(lang: str) -> InlineKeyboardMarkup:
    send = {"ru": "Отправить", "en": "Send", "uk": "Надіслати"}
    edit = {"ru": "Изменить", "en": "Edit", "uk": "Змінити"}
    cancel = {"ru": "Отмена", "en": "Cancel", "uk": "Скасувати"}
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="✅ " + send.get(lang, "Send"), callback_data="preview:send"),
            InlineKeyboardButton(text="✏️ " + edit.get(lang, "Edit"), callback_data="preview:edit"),
        ],
        [InlineKeyboardButton(text="❌ " + cancel.get(lang, "Cancel"), callback_data="preview:cancel")],
    ])


def _admin_kb(post_id: int, user_id: int, lang: str, public_id: Optional[int] = None) -> InlineKeyboardMarkup:
    a = lambda k: t(lang, k)
    btns = [
        [
            InlineKeyboardButton(text=a("admin_approved"), callback_data=f"admin:approve:{post_id}"),
            InlineKeyboardButton(text=a("admin_rejected"), callback_data=f"admin:reject:{post_id}"),
        ],
        [
            InlineKeyboardButton(text=a("admin_banned"), callback_data=f"admin:ban:{post_id}:{user_id}"),
            InlineKeyboardButton(text=a("admin_warn"), callback_data=f"admin:warn:{post_id}:{user_id}"),
        ],
        [
            InlineKeyboardButton(text=a("admin_queue"), callback_data="admin:queue"),
            InlineKeyboardButton(text=a("admin_stats"), callback_data="admin:stats"),
        ],
    ]
    if public_id:
        ch = str(cfg.channel_id).replace("@", "")
        btns.append([InlineKeyboardButton(text=a("admin_post_link").format(public_id=public_id), url=f"https://t.me/{ch}/{public_id}")])
    return InlineKeyboardMarkup(inline_keyboard=btns)


@dp.startup()
async def _on_startup():
    await db.connect()
    logging.info("Bot started, DB connected")


@dp.shutdown()
async def _on_shutdown():
    await db.close()
    logging.info("Bot stopped, DB closed")


async def _build_user_card(user_id: int, user: Any, lang: str) -> str:
    db_user = await db.get_user(user_id)
    counts = await db.user_post_counts(user_id)
    activity = await db.user_activity_counts(user_id)
    banned = await db.is_banned(user_id)
    warn_count = await db.count_warns(user_id)

    bio = "—"
    photos_count = "?"
    has_photo = "—"
    extra_usernames = "—"
    has_private_forwards = "—"
    has_restricted_media = "—"
    birthdate = "—"
    emoji_status = "—"
    accent_color = "—"
    profile_accent = "—"
    background_emoji = "—"
    personal_chat = "—"
    max_reactions = "—"

    try:
        chat = await bot.get_chat(user_id)
        bio = chat.bio or "—"

        try:
            photos = await bot.get_user_profile_photos(user_id, limit=100)
            photos_count = photos.total_count if photos else 0
            has_photo = _yn(photos_count > 0)
        except Exception:
            photos_count = "?"
            has_photo = "?"

        au = getattr(chat, "active_usernames", None)
        if au:
            extra_usernames = ", ".join(f"@{u}" for u in au)

        has_private_forwards = _yn(getattr(chat, "has_private_forwards", None))
        has_restricted_media = _yn(getattr(chat, "has_restricted_voice_and_video_messages", None))

        bd = getattr(chat, "birthdate", None)
        if bd:
            year = getattr(bd, "year", None)
            birthdate = f"{bd.day:02d}.{bd.month:02d}.{year}" if year else f"{bd.day:02d}.{bd.month:02d}"

        es = getattr(chat, "emoji_status_custom_emoji_id", None)
        if es:
            emoji_status = f"<code>{es}</code>"

        ac = getattr(chat, "accent_color_id", None)
        if ac is not None:
            accent_color = str(ac)

        pac = getattr(chat, "profile_accent_color_id", None)
        if pac is not None:
            profile_accent = str(pac)

        be = getattr(chat, "background_custom_emoji_id", None)
        if be:
            background_emoji = f"<code>{be}</code>"

        pbe = getattr(chat, "profile_background_custom_emoji_id", None)
        if pbe:
            background_emoji += f" / профиль: <code>{pbe}</code>"

        pc = getattr(chat, "personal_chat", None)
        if pc:
            personal_chat = f"<code>{pc.id}</code>"

        mr = getattr(chat, "max_reaction_count", None)
        if mr is not None:
            max_reactions = str(mr)

    except Exception:
        pass

    first_seen = "—"
    last_seen = "—"
    if db_user:
        if db_user["first_seen"]:
            first_seen = datetime.fromtimestamp(db_user["first_seen"]).strftime("%Y-%m-%d %H:%M:%S")
        if db_user["last_seen"]:
            last_seen = datetime.fromtimestamp(db_user["last_seen"]).strftime("%Y-%m-%d %H:%M:%S")

    username = f"@{_esc(user.username)}" if user.username else "—"
    profile_link = f'<a href="tg://user?id={user_id}">открыть профиль</a>'
    client_language = user.language_code or (db_user["language_code"] if db_user else None)
    account_age = "—"
    if db_user and db_user["first_seen"]:
        account_age = f"в базе с {_ts(datetime.fromtimestamp(db_user['first_seen']))}"

    parts = [
        "👤 <b>ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ</b>",
        "━━━━━━━━━━━━━━━━",
        f"Имя: <b>{_esc(user.full_name)}</b>",
        f"Username: {username}",
        f"Другие username: {extra_usernames}",
        f"ID: <code>{user_id}</code> · {profile_link}",
        "",
        "🧾 <b>АККАУНТ</b>",
        f"Язык Telegram: {_esc(client_language)}",
        f"Premium: {_yn(bool(user.is_premium))} · Бот: {_yn(user.is_bot)}",
        f"Добавлен в меню: {_yn(getattr(user, 'added_to_attachment_menu', None))}",
        f"Пересылки скрыты: {has_private_forwards}",
        f"Ограничение голосовых/видео: {has_restricted_media}",
        f"Дата рождения (если открыта): {birthdate}",
        "",
        "🖼 <b>ПРОФИЛЬ</b>",
        f"Аватаров: {photos_count} · Есть аватар: {has_photo}",
        f"О себе: {_esc(bio)}",
        f"Emoji-статус: {emoji_status}",
        f"Цвет профиля: {profile_accent} · Цвет аккаунта: {accent_color}",
        f"Фон: {background_emoji}",
        f"Личный чат: {personal_chat} · Реакций: {max_reactions}",
        "",
        "📊 <b>ИСТОРИЯ В БОТЕ</b>",
        f"Статус: {'🔨 заблокирован' if banned else '✅ активен'} · Варнов: {warn_count}",
        f"Первый контакт: {first_seen}",
        f"Последний контакт: {last_seen}",
        f"Записей: {counts['total']} · ⏳ {counts['pending']} · ✅ {counts['published']} · ❌ {counts['rejected']}",
        f"Комментарии: {activity['comments']} · Голоса: {activity['votes']} · Жалобы: {activity['reports']}",
        f"{account_age}",
    ]
    return chr(10).join(parts)


async def _build_message_card(msg: Message, lang: str) -> str:
    text = msg.text or msg.caption or ""
    chars = len(text)
    words = len(text.split()) if text else 0

    ct = msg.content_type
    try:
        content_type = ct.value if hasattr(ct, "value") else str(ct)
    except Exception:
        content_type = str(ct)

    forward_info = "—"
    if msg.forward_origin:
        forward_info = f"Да ({msg.forward_origin.type})"

    protected = _yn(getattr(msg, "has_protected_content", None))
    entities = getattr(msg, "entities", None) or getattr(msg, "caption_entities", None) or []
    entity_types = ", ".join(sorted({
        getattr(entity.type, "value", str(entity.type)) for entity in entities
    })) or "—"
    via_bot = getattr(msg, "via_bot", None)
    via_bot_name = f"@{via_bot.username}" if via_bot and via_bot.username else "—"
    media = msg.photo[-1] if msg.photo else (
        msg.video or msg.audio or msg.voice or msg.document or msg.animation or msg.video_note
    )

    parts = [
        t(lang, "admin_msg"),
        f"Тип: {_esc(content_type)}",
        f"Время (UTC+локаль сервера): {_ts(msg.date)}",
        f"Unix time: <code>{int(msg.date.timestamp()) if msg.date else 0}</code>",
        f"Chat ID: <code>{msg.chat.id}</code>",
        f"Chat type: {_esc(msg.chat.type)}",
        f"Message ID: <code>{msg.message_id}</code>",
        f"Символов: {chars}, слов: {words}",
        f"Сущности текста: {_esc(entity_types)}",
        f"Через бота: {_esc(via_bot_name)}",
        f"Переслано: {forward_info}",
        f"Защищенный контент: {protected}",
    ]
    if media:
        media_parts = []
        for field in ("file_id", "file_unique_id", "file_size", "width", "height", "duration", "performer", "title", "mime_type"):
            value = getattr(media, field, None)
            if value is not None:
                media_parts.append(f"{field}={_esc(value)}")
        if media_parts:
            parts.append("Медиа: " + ", ".join(media_parts))
    if msg.media_group_id:
        parts.append(f"Media Group ID: <code>{msg.media_group_id}</code>")
    if msg.reply_to_message:
        parts.append(f"Ответ на сообщение ID: <code>{msg.reply_to_message.message_id}</code>")
    if msg.edit_date:
        parts.append(f"Изменено: {_ts(msg.edit_date)}")
    if getattr(msg, "author_signature", None):
        parts.append(f"Подпись автора: {_esc(msg.author_signature)}")
    if getattr(msg, "sender_chat", None):
        parts.append(f"Чат-отправитель: <code>{msg.sender_chat.id}</code>")
    return chr(10).join(parts)


@dp.message(Command("start"))
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    u = message.from_user
    await _audit(u.id, "Bot /start", "telegram_user")
    await db.upsert_user(
        u.id, u.first_name, u.last_name, u.username,
        u.language_code, bool(u.is_premium)
    )
    ui_lang = await db.get_ui_lang(u.id)
    if not ui_lang:
        await message.answer("Выбери язык / Choose language / Обери мову:", reply_markup=_lang_kb())
        return
    await message.answer(t(ui_lang, "welcome", min_len=cfg.min_text_len))


@dp.callback_query(F.data.startswith("lang:"))
async def cb_lang(callback: CallbackQuery):
    lang = callback.data.split(":")[1]
    await _audit(callback.from_user.id, "Bot language change", lang)
    await db.set_ui_lang(callback.from_user.id, lang)
    await callback.message.delete()
    await callback.message.answer(t(lang, "welcome", min_len=cfg.min_text_len))


@dp.message(Command("language"))
async def cmd_language(message: Message):
    await message.answer(t(await _lang(message.from_user.id), "choose"), reply_markup=_lang_kb())


@dp.message(Command("my_posts"))
async def cmd_my_posts(message: Message):
    uid = message.from_user.id
    await _audit(uid, "Bot my_posts", "")
    lang = await _lang(uid)
    posts = await db.user_posts(uid, limit=20)
    if not posts:
        await message.answer(t(lang, "my_posts_empty"))
        return
    items = []
    for p in posts:
        st = p["status"]
        if st == "pending":
            line = t(lang, "status_pending")
        elif st == "published":
            line = t(lang, "status_published", public_id=p["public_id"] or "?")
        elif st == "rejected":
            line = t(lang, "status_rejected")
        else:
            line = st
        items.append(f"#{p['id']} — {line}")
    await message.answer(t(lang, "my_posts", items=chr(10).join(items)))


pending_media_groups: Dict[str, Dict[str, Any]] = {}


@dp.message(F.text | F.photo | F.video | F.voice | F.audio | F.document | F.video_note | F.animation)
async def handle_incoming(message: Message, state: FSMContext):
    uid = message.from_user.id
    lang = await _lang(uid)

    if await db.is_banned(uid):
        await _audit(uid, "Bot blocked message (banned)", "message")
        await message.answer(t(lang, "banned"))
        return

    if not await db.get_ui_lang(uid):
        await message.answer(t("ru", "need_lang"))
        return

    last = await db.last_post_time(uid)
    if last and (time.time() - last) < cfg.cooldown_seconds:
        await _audit(uid, "Bot rate limit cooldown", "message")
        wait = int(cfg.cooldown_seconds - (time.time() - last))
        await message.answer(t(lang, "wait", wait=wait))
        return

    if await db.posts_last_hour(uid) >= cfg.max_posts_per_hour:
        await _audit(uid, "Bot rate limit hourly", "message")
        await message.answer(t(lang, "flood", limit=cfg.max_posts_per_hour))
        return

    txt = message.text or message.caption
    if message.content_type.value == "text" and (not txt or len(txt) < cfg.min_text_len):
        await message.answer(t(lang, "too_short", min_len=cfg.min_text_len))
        return

    bad = await db.check_banned_words(txt)
    if bad:
        await _audit(uid, "Bot banned words rejected", ",".join(bad))
        await message.answer(t(lang, "banned_words", words=", ".join(bad)))
        return

    file_id = None
    if message.photo:
        file_id = message.photo[-1].file_id
    elif message.video:
        file_id = message.video.file_id
    elif message.voice:
        file_id = message.voice.file_id
    elif message.audio:
        file_id = message.audio.file_id
    elif message.document:
        file_id = message.document.file_id
    elif message.video_note:
        file_id = message.video_note.file_id
    elif message.animation:
        file_id = message.animation.file_id

    if await db.find_duplicate(uid, txt, file_id):
        await _audit(uid, "Bot duplicate rejected", "message")
        await message.answer(t(lang, "duplicate"))
        return

    if message.media_group_id:
        mgid = message.media_group_id
        if mgid not in pending_media_groups:
            pending_media_groups[mgid] = {"items": [], "user_id": uid, "timer": None}
            pending_media_groups[mgid]["timer"] = asyncio.create_task(_mg_timeout(mgid))
        pending_media_groups[mgid]["items"].append({
            "message": message,
            "kind": message.content_type.value,
            "file_id": file_id,
            "caption": message.caption,
        })
        if len(pending_media_groups[mgid]["items"]) == 1:
            await message.answer(t(lang, "accepted"))
        return

    await _show_preview(message, state, txt, file_id, message.content_type.value)


async def _mg_timeout(mgid: str):
    await asyncio.sleep(cfg.media_group_timeout)
    data = pending_media_groups.pop(mgid, None)
    if not data or not data["items"]:
        return
    first = data["items"][0]
    msg = first["message"]
    uid = data['user_id']
    lang = await _lang(uid)

    post_id = await db.add_post(
        user_id=uid, kind="media_group", text=first["caption"],
        file_id=first["file_id"], media_group_id=mgid
    )
    for it in data['items'][1:]:
        await db.add_media_group_item(post_id, it["kind"], it["file_id"], it["caption"])

    await _notify_admins(post_id, msg, is_media_group=True, items=data['items'])
    await _audit(uid, "Bot post submitted", post_id)
    await msg.answer(t(lang, "sent"))


async def _show_preview(message: Message, state: FSMContext, text: Optional[str], file_id: Optional[str], kind: str):
    lang = await _lang(message.from_user.id)
    await state.update_data(preview_text=text, preview_file_id=file_id, preview_kind=kind)
    caption = f"<b>{t(lang, 'preview_title')}</b>" + chr(10) + chr(10) + f"{t(lang, 'preview_text')}"
    if text:
        caption += chr(10) + chr(10) + f"{text}"
    kb = _preview_kb(lang)

    if kind == "text":
        await message.answer(caption, reply_markup=kb)
    elif kind == "photo" and file_id:
        await message.answer_photo(file_id, caption=caption, reply_markup=kb)
    elif kind == "video" and file_id:
        await message.answer_video(file_id, caption=caption, reply_markup=kb)
    elif kind == "voice" and file_id:
        await message.answer_voice(file_id, caption=caption, reply_markup=kb)
    elif kind == "audio" and file_id:
        await message.answer_audio(file_id, caption=caption, reply_markup=kb)
    elif kind == "document" and file_id:
        await message.answer_document(file_id, caption=caption, reply_markup=kb)
    elif kind == "video_note" and file_id:
        await message.answer_video_note(file_id)
        await message.answer(caption, reply_markup=kb)
    elif kind == "animation" and file_id:
        await message.answer_animation(file_id, caption=caption, reply_markup=kb)
    else:
        await message.answer(caption, reply_markup=kb)
    await state.set_state(UserState.preview)


@dp.callback_query(UserState.preview, F.data == "preview:cancel")
async def cb_preview_cancel(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    await callback.message.delete()
    await callback.message.answer(t(await _lang(callback.from_user.id), "cancelled"))


@dp.callback_query(UserState.preview, F.data == "preview:edit")
async def cb_preview_edit(callback: CallbackQuery, state: FSMContext):
    await callback.message.delete()
    await callback.message.answer(t(await _lang(callback.from_user.id), "edit_prompt"))
    await state.set_state(UserState.editing)


@dp.message(UserState.editing, F.text)
async def st_editing(message: Message, state: FSMContext):
    data = await state.get_data()
    kind = data.get("preview_kind")
    file_id = data.get("preview_file_id")
    await state.update_data(preview_text=message.text)
    await _show_preview(message, state, message.text, file_id, kind)
    try:
        await message.delete()
    except Exception:
        pass


@dp.callback_query(UserState.preview, F.data == "preview:send")
async def cb_preview_send(callback: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    uid = callback.from_user.id
    lang = await _lang(uid)
    text = data.get("preview_text")
    file_id = data.get("preview_file_id")
    kind = data.get("preview_kind")

    post_id = await db.add_post(user_id=uid, kind=kind or "text", text=text, file_id=file_id)
    await _audit(uid, "Bot post submitted", post_id)
    await state.clear()
    await callback.message.delete()
    await callback.message.answer(t(lang, "sent"))
    await _notify_admins_simple(post_id, uid, text, file_id, kind, callback.from_user)


async def _notify_admins_simple(post_id: int, user_id: int, text: Optional[str], file_id: Optional[str], kind: str, from_user: Any):
    for admin_id in cfg.admin_ids:
        lang = await _lang(admin_id)
        user_card = await _build_user_card(user_id, from_user, lang)
        # Build message card manually (no Message object in preview flow)
        txt = text or ""
        chars = len(txt)
        words = len(txt.split()) if txt else 0
        msg_parts = [
            t(lang, "admin_msg"),
            f"Тип: {_esc(kind)}",
            f"Символов: {chars}, слов: {words}",
        ]
        msg_card = chr(10).join(msg_parts)
        header = t(lang, "admin_new_post", post_id=post_id) + chr(10) + t(lang, "admin_not_published")
        caption = header + chr(10) + chr(10) + user_card + chr(10) + chr(10) + msg_card
        kb = _admin_kb(post_id, user_id, lang)
        try:
            if kind == "text" or not file_id:
                await bot.send_message(admin_id, caption, reply_markup=kb, parse_mode="HTML", disable_web_page_preview=True)
            elif kind == "photo":
                await bot.send_photo(admin_id, file_id, caption=caption, reply_markup=kb, parse_mode="HTML")
            elif kind == "video":
                await bot.send_video(admin_id, file_id, caption=caption, reply_markup=kb, parse_mode="HTML")
            elif kind == "voice":
                await bot.send_voice(admin_id, file_id, caption=caption, reply_markup=kb, parse_mode="HTML")
            elif kind == "audio":
                await bot.send_audio(admin_id, file_id, caption=caption, reply_markup=kb, parse_mode="HTML")
            elif kind == "document":
                await bot.send_document(admin_id, file_id, caption=caption, reply_markup=kb, parse_mode="HTML")
            elif kind == "animation":
                await bot.send_animation(admin_id, file_id, caption=caption, reply_markup=kb, parse_mode="HTML")
            else:
                await bot.send_message(admin_id, caption, reply_markup=kb, parse_mode="HTML", disable_web_page_preview=True)
        except Exception as e:
            logging.error(f"Notify admin {admin_id} error: {e}")


async def _notify_admins(post_id: int, message: Message, is_media_group: bool = False, items: Optional[List[Dict]] = None):
    for admin_id in cfg.admin_ids:
        lang = await _lang(admin_id)
        user_card = await _build_user_card(message.from_user.id, message.from_user, lang)
        msg_card = await _build_message_card(message, lang)
        header = t(lang, "admin_new_post", post_id=post_id) + chr(10) + t(lang, "admin_not_published")
        caption = header + chr(10) + chr(10) + user_card + chr(10) + chr(10) + msg_card
        if is_media_group and items:
            caption += chr(10) + f"📎 Media group: {len(items)} items"
        kb = _admin_kb(post_id, message.from_user.id, lang)

        try:
            if is_media_group and items:
                media = []
                for i, it in enumerate(items):
                    cap = caption if i == 0 else None
                    k = it["kind"]
                    fid = it["file_id"]
                    if k == "photo":
                        media.append(InputMediaPhoto(media=fid, caption=cap, parse_mode="HTML"))
                    elif k == "video":
                        media.append(InputMediaVideo(media=fid, caption=cap, parse_mode="HTML"))
                    elif k == "audio":
                        media.append(InputMediaAudio(media=fid, caption=cap, parse_mode="HTML"))
                    elif k == "document":
                        media.append(InputMediaDocument(media=fid, caption=cap, parse_mode="HTML"))
                if media:
                    await bot.send_media_group(admin_id, media=media)
                    await bot.send_message(admin_id, f"👆 #{post_id}", reply_markup=kb)
                else:
                    await bot.send_message(admin_id, caption, reply_markup=kb, parse_mode="HTML", disable_web_page_preview=True)
            else:
                fid = None
                if message.photo:
                    fid = message.photo[-1].file_id
                elif message.video:
                    fid = message.video.file_id
                elif message.voice:
                    fid = message.voice.file_id
                elif message.audio:
                    fid = message.audio.file_id
                elif message.document:
                    fid = message.document.file_id
                elif message.video_note:
                    fid = message.video_note.file_id
                elif message.animation:
                    fid = message.animation.file_id

                ct = message.content_type.value
                if ct == "text":
                    await bot.send_message(admin_id, caption, reply_markup=kb, parse_mode="HTML", disable_web_page_preview=True)
                elif ct == "photo" and fid:
                    await bot.send_photo(admin_id, fid, caption=caption, reply_markup=kb, parse_mode="HTML")
                elif ct == "video" and fid:
                    await bot.send_video(admin_id, fid, caption=caption, reply_markup=kb, parse_mode="HTML")
                elif ct == "voice" and fid:
                    await bot.send_voice(admin_id, fid, caption=caption, reply_markup=kb, parse_mode="HTML")
                elif ct == "audio" and fid:
                    await bot.send_audio(admin_id, fid, caption=caption, reply_markup=kb, parse_mode="HTML")
                elif ct == "document" and fid:
                    await bot.send_document(admin_id, fid, caption=caption, reply_markup=kb, parse_mode="HTML")
                elif ct == "video_note" and fid:
                    await bot.send_video_note(admin_id, fid)
                    await bot.send_message(admin_id, caption, reply_markup=kb, parse_mode="HTML", disable_web_page_preview=True)
                elif ct == "animation" and fid:
                    await bot.send_animation(admin_id, fid, caption=caption, reply_markup=kb, parse_mode="HTML")
                else:
                    await bot.send_message(admin_id, caption, reply_markup=kb, parse_mode="HTML", disable_web_page_preview=True)
        except Exception as e:
            logging.error(f"Notify admin {admin_id} error: {e}")


@dp.callback_query(F.data.startswith("admin:approve:"))
async def cb_approve(callback: CallbackQuery):
    admin_id = callback.from_user.id
    lang = await _lang(admin_id)
    if admin_id not in cfg.admin_ids:
        await callback.answer(t(lang, "admin_no_access"), show_alert=True)
        return
    post_id = int(callback.data.split(":")[2])
    post = await db.get_post(post_id)
    if not post or post["status"] != "pending":
        await callback.answer(t(lang, "admin_not_found"))
        return

    public_id = await db.next_public_id()
    try:
        channel_id = cfg.channel_id
        if not str(channel_id).startswith(("@", "-100")):
            channel_id = "@" + str(channel_id)
        text = post["text"] or ""
        pub_text = f"#{public_id}" + chr(10) + chr(10) + text if text else f"#{public_id}"
        fid = post["file_id"]
        kind = post["kind"]
        msg = None

        if kind == "text":
            msg = await bot.send_message(channel_id, pub_text)
        elif kind == "photo":
            msg = await bot.send_photo(channel_id, fid, caption=pub_text)
        elif kind == "video":
            msg = await bot.send_video(channel_id, fid, caption=pub_text)
        elif kind == "voice":
            msg = await bot.send_voice(channel_id, fid, caption=pub_text)
        elif kind == "audio":
            msg = await bot.send_audio(channel_id, fid, caption=pub_text)
        elif kind == "document":
            msg = await bot.send_document(channel_id, fid, caption=pub_text)
        elif kind == "animation":
            msg = await bot.send_animation(channel_id, fid, caption=pub_text)
        elif kind == "media_group":
            items = await db.get_media_group_items(post_id)
            media = []
            for i, it in enumerate(items):
                cap = pub_text if i == 0 else None
                k = it["kind"]
                if k == "photo":
                    media.append(InputMediaPhoto(media=it["file_id"], caption=cap))
                elif k == "video":
                    media.append(InputMediaVideo(media=it["file_id"], caption=cap))
                elif k == "audio":
                    media.append(InputMediaAudio(media=it["file_id"], caption=cap))
                elif k == "document":
                    media.append(InputMediaDocument(media=it["file_id"], caption=cap))
            msgs = await bot.send_media_group(channel_id, media=media)
            msg = msgs[0] if msgs else None
        else:
            msg = await bot.send_message(channel_id, pub_text)

        if msg:
            await db.approve(post_id, public_id)
            await db.set_channel_message_id(post_id, msg.message_id)

        await db.log_admin_action(admin_id, "approve", post_id)
        await _audit(admin_id, "Bot approve", post_id)
        await callback.answer(t(lang, "admin_approve_ok"))

        old_text = callback.message.text or callback.message.caption or ""
        await callback.message.edit_text(
            f"✅ <b>{t(lang, 'admin_approved')}</b> #{public_id}" + chr(10) + chr(10) + old_text,
            reply_markup=None, parse_mode="HTML"
        )

        try:
            ul = await db.get_ui_lang(post["user_id"]) or "ru"
            await bot.send_message(post["user_id"], t(ul, "published", public_id=public_id))
        except Exception:
            pass
    except Exception as e:
        logging.error(f"Publish error: {e}")
        target = cfg.channel_id
        if not str(target).startswith(("@", "-100")):
            target = "@" + str(target)
        await callback.answer(
            t(lang, "admin_publish_error", error=f"{e} (канал: {target})"),
            show_alert=True,
        )


@dp.callback_query(F.data.startswith("admin:reject:"))
async def cb_reject(callback: CallbackQuery, state: FSMContext):
    admin_id = callback.from_user.id
    lang = await _lang(admin_id)
    if admin_id not in cfg.admin_ids:
        await callback.answer(t(lang, "admin_no_access"), show_alert=True)
        return
    post_id = int(callback.data.split(":")[2])
    post = await db.get_post(post_id)
    if not post or post["status"] != "pending":
        await callback.answer(t(lang, "admin_not_found"))
        return
    await state.update_data(reject_post_id=post_id)
    await callback.message.answer(t(lang, "admin_enter_reject"))
    await state.set_state(AdminState.reject_reason)
    await callback.answer()


@dp.message(AdminState.reject_reason, F.text)
async def st_reject_reason(message: Message, state: FSMContext):
    data = await state.get_data()
    post_id = data.get("reject_post_id")
    reason = message.text if message.text != "/skip" else None
    post = await db.get_post(post_id)
    if post:
        await db.reject(post_id, reason, message.from_user.id)
        await db.log_admin_action(message.from_user.id, "reject", post_id, reason)
        await _audit(message.from_user.id, "Bot reject", f"{post_id}:{reason or ''}")
        try:
            ul = await db.get_ui_lang(post["user_id"]) or "ru"
            if reason:
                await bot.send_message(post["user_id"], t(ul, "rejected_reason", reason=reason))
            else:
                await bot.send_message(post["user_id"], t(ul, "rejected"))
        except Exception:
            pass
    await state.clear()
    await message.answer(t(await _lang(message.from_user.id), "admin_rejected_ok"))


@dp.callback_query(F.data.startswith("admin:ban:"))
async def cb_ban(callback: CallbackQuery, state: FSMContext):
    admin_id = callback.from_user.id
    lang = await _lang(admin_id)
    if admin_id not in cfg.admin_ids:
        await callback.answer(t(lang, "admin_no_access"), show_alert=True)
        return
    parts = callback.data.split(":")
    post_id = int(parts[2])
    user_id = int(parts[3])
    await state.update_data(ban_user_id=user_id, ban_post_id=post_id)
    await callback.message.answer(t(lang, "admin_enter_ban"))
    await state.set_state(AdminState.ban_reason)
    await callback.answer()


@dp.message(AdminState.ban_reason, F.text)
async def st_ban_reason(message: Message, state: FSMContext):
    data = await state.get_data()
    user_id = data.get("ban_user_id")
    post_id = data.get("ban_post_id")
    reason = message.text if message.text != "/skip" else "No reason"
    await db.ban(user_id, reason)
    await db.log_admin_action(message.from_user.id, "ban", post_id, reason)
    await _audit(message.from_user.id, "Bot ban", user_id)
    await state.clear()
    lang = await _lang(message.from_user.id)
    await message.answer(t(lang, "admin_banned_ok", user_id=user_id, reason=reason))


@dp.callback_query(F.data.startswith("admin:warn:"))
async def cb_warn(callback: CallbackQuery):
    admin_id = callback.from_user.id
    lang = await _lang(admin_id)
    if admin_id not in cfg.admin_ids:
        await callback.answer(t(lang, "admin_no_access"), show_alert=True)
        return
    parts = callback.data.split(":")
    post_id = int(parts[2])
    user_id = int(parts[3])
    await db.add_warn(user_id, t(lang, "admin_warn"), post_id, admin_id)
    await db.log_admin_action(admin_id, "warn", post_id)
    await _audit(admin_id, "Bot warn", user_id)
    count = await db.count_warns(user_id)
    await callback.answer(t(lang, "admin_warn_ok", count=count))
    if count >= 3:
        await db.ban(user_id, "Auto-ban for 3 warns")
        await _audit(admin_id, "Bot auto-ban", user_id)
        await callback.message.answer(t(lang, "admin_auto_ban", user_id=user_id))


@dp.callback_query(F.data == "admin:queue")
async def cb_queue(callback: CallbackQuery):
    admin_id = callback.from_user.id
    lang = await _lang(admin_id)
    if admin_id not in cfg.admin_ids:
        await callback.answer(t(lang, "admin_no_access"), show_alert=True)
        return
    await _audit(admin_id, "Bot queue viewed", "")
    pending = await db.list_pending()
    if not pending:
        await callback.message.answer(t(lang, "admin_queue_empty"))
        return
    lines_list = [t(lang, "admin_queue_title", count=len(pending))]
    for p in pending[:20]:
        un = p["user_name"] or "?"
        um = f"@{p['username']}" if p["username"] else "—"
        lines_list.append(f"#{p['id']} | {_esc(un)} ({um}) | {p['kind']} | {_ts(datetime.fromtimestamp(p['created_at']))}")
    await callback.message.answer(chr(10).join(lines_list), parse_mode="HTML")
    await callback.answer()


@dp.callback_query(F.data == "admin:stats")
async def cb_stats(callback: CallbackQuery):
    admin_id = callback.from_user.id
    lang = await _lang(admin_id)
    if admin_id not in cfg.admin_ids:
        await callback.answer(t(lang, "admin_no_access"), show_alert=True)
        return
    await _audit(admin_id, "Bot stats viewed", "")
    s = await db.stats()
    text = t(lang, "admin_stats_title") + chr(10) + chr(10)
    text += t(lang, "admin_users", count=s["users"]) + chr(10)
    text += t(lang, "admin_authors", count=s["authors"]) + chr(10) + chr(10)
    text += t(lang, "admin_posts") + chr(10)
    text += t(lang, "admin_pending", count=s["pending"]) + chr(10)
    text += t(lang, "admin_published", count=s["published"]) + chr(10)
    text += t(lang, "admin_rejected_count", count=s["rejected"]) + chr(10)
    text += t(lang, "admin_deleted", count=s["deleted"]) + chr(10) + chr(10)
    text += t(lang, "admin_bans", count=s["bans"]) + chr(10)
    text += t(lang, "admin_warns", count=s["warns"]) + chr(10)
    text += t(lang, "admin_reports", count=s["reports"]) + chr(10)
    text += t(lang, "admin_last_id", count=s["last_public_id"])
    await callback.message.answer(text, parse_mode="HTML")
    await callback.answer()


@dp.message(Command("queue"))
async def cmd_queue(message: Message):
    admin_id = message.from_user.id
    lang = await _lang(admin_id)
    if admin_id not in cfg.admin_ids:
        return
    await _audit(admin_id, "Bot queue viewed", "")
    pending = await db.list_pending()
    if not pending:
        await message.answer(t(lang, "admin_queue_empty"))
        return
    lines_list = [t(lang, "admin_queue_title", count=len(pending))]
    for p in pending[:20]:
        un = p["user_name"] or "?"
        um = f"@{p['username']}" if p["username"] else "—"
        lines_list.append(f"#{p['id']} | {_esc(un)} ({um}) | {p['kind']} | {_ts(datetime.fromtimestamp(p['created_at']))}")
    await message.answer(chr(10).join(lines_list), parse_mode="HTML")


@dp.message(Command("stats"))
async def cmd_stats(message: Message):
    admin_id = message.from_user.id
    lang = await _lang(admin_id)
    if admin_id not in cfg.admin_ids:
        return
    await _audit(admin_id, "Bot stats viewed", "")
    s = await db.stats()
    text = t(lang, "admin_stats_title") + chr(10) + chr(10)
    text += t(lang, "admin_users", count=s["users"]) + chr(10)
    text += t(lang, "admin_authors", count=s["authors"]) + chr(10) + chr(10)
    text += t(lang, "admin_posts") + chr(10)
    text += t(lang, "admin_pending", count=s["pending"]) + chr(10)
    text += t(lang, "admin_published", count=s["published"]) + chr(10)
    text += t(lang, "admin_rejected_count", count=s["rejected"]) + chr(10)
    text += t(lang, "admin_deleted", count=s["deleted"]) + chr(10) + chr(10)
    text += t(lang, "admin_bans", count=s["bans"]) + chr(10)
    text += t(lang, "admin_warns", count=s["warns"]) + chr(10)
    text += t(lang, "admin_reports", count=s["reports"]) + chr(10)
    text += t(lang, "admin_last_id", count=s["last_public_id"])
    await message.answer(text, parse_mode="HTML")


@dp.message(Command("ban"))
async def cmd_ban(message: Message, command: CommandObject):
    admin_id = message.from_user.id
    lang = await _lang(admin_id)
    if admin_id not in cfg.admin_ids:
        return
    if not command.args:
        await message.answer("Usage: /ban <user_id> [reason]")
        return
    args = command.args.split(maxsplit=1)
    user_id = int(args[0])
    reason = args[1] if len(args) > 1 else ""
    await db.ban(user_id, reason)
    await _audit(admin_id, "Bot ban", user_id)
    await message.answer(t(lang, "admin_banned_ok", user_id=user_id, reason=reason))


@dp.message(Command("unban"))
async def cmd_unban(message: Message, command: CommandObject):
    admin_id = message.from_user.id
    if admin_id not in cfg.admin_ids:
        return
    if not command.args:
        await message.answer("Usage: /unban <user_id>")
        return
    user_id = int(command.args.strip())
    if await db.unban(user_id):
        await _audit(admin_id, "Bot unban", user_id)
        await message.answer(f"User {user_id} unbanned.")
    else:
        await message.answer("User was not banned.")


@dp.message(Command("warn"))
async def cmd_warn(message: Message, command: CommandObject):
    admin_id = message.from_user.id
    lang = await _lang(admin_id)
    if admin_id not in cfg.admin_ids:
        return
    if not command.args:
        await message.answer("Usage: /warn <user_id> [reason]")
        return
    args = command.args.split(maxsplit=1)
    user_id = int(args[0])
    reason = args[1] if len(args) > 1 else ""
    await db.add_warn(user_id, reason, admin_id=admin_id)
    await _audit(admin_id, "Bot warn", user_id)
    count = await db.count_warns(user_id)
    await message.answer(t(lang, "admin_warn_ok", count=count))
    if count >= 3:
        await db.ban(user_id, "Auto-ban for 3 warns")
        await message.answer(t(lang, "admin_auto_ban", user_id=user_id))


@dp.message(Command("addword"))
async def cmd_addword(message: Message, command: CommandObject):
    if message.from_user.id not in cfg.admin_ids:
        return
    if not command.args:
        await message.answer("Usage: /addword <word>")
        return
    word = command.args.strip().lower()
    if await db.add_banned_word(word):
        await _audit(admin_id, "Bot add banned word", word)
        await message.answer(f"Word '{word}' added to ban-list.")
    else:
        await message.answer("Word already exists.")


@dp.message(Command("delword"))
async def cmd_delword(message: Message, command: CommandObject):
    if message.from_user.id not in cfg.admin_ids:
        return
    if not command.args:
        await message.answer("Usage: /delword <word>")
        return
    word = command.args.strip().lower()
    await db.remove_banned_word(word)
    await _audit(admin_id, "Bot remove banned word", word)
    await message.answer(f"Word '{word}' removed from ban-list.")


@dp.message(Command("words"))
async def cmd_words(message: Message):
    if message.from_user.id not in cfg.admin_ids:
        return
    words = await db.list_banned_words()
    if not words:
        await message.answer("Ban-list is empty.")
    else:
        await message.answer("🚫 Banned words:" + chr(10) + chr(10).join(f"- {w}" for w in words))


@dp.message(Command("broadcast"))
async def cmd_broadcast(message: Message, command: CommandObject):
    if message.from_user.id not in cfg.admin_ids:
        return
    if not command.args:
        await message.answer("Usage: /broadcast <text>")
        return
    await bot.send_message(cfg.channel_id, command.args)
    await _audit(message.from_user.id, "Bot broadcast", cfg.channel_id)
    await message.answer("Sent to channel.")


@dp.message(Command("comment"))
async def cmd_comment(message: Message, command: CommandObject, state: FSMContext):
    if not command.args:
        await message.answer("Usage: /comment <public_id>")
        return
    public_id = int(command.args.strip())
    await state.update_data(comment_public_id=public_id)
    lang = await _lang(message.from_user.id)
    await message.answer(t(lang, "comment_prompt", public_id=public_id))
    await state.set_state(UserState.commenting)


@dp.message(UserState.commenting, F.text)
async def st_comment(message: Message, state: FSMContext):
    data = await state.get_data()
    public_id = data.get("comment_public_id")
    await db.add_comment(public_id, message.from_user.id, message.text)
    await _audit(message.from_user.id, "Bot comment", public_id)
    await state.clear()
    lang = await _lang(message.from_user.id)
    await message.answer(t(lang, "comment_sent"))


@dp.message(Command("report"))
async def cmd_report(message: Message, command: CommandObject, state: FSMContext):
    if not command.args:
        await message.answer("Usage: /report <public_id>")
        return
    public_id = int(command.args.strip())
    await state.update_data(report_public_id=public_id)
    lang = await _lang(message.from_user.id)
    await message.answer(t(lang, "report_reason"))
    await state.set_state(UserState.reporting)


@dp.message(UserState.reporting, F.text)
async def st_report(message: Message, state: FSMContext):
    data = await state.get_data()
    public_id = data.get("report_public_id")
    await db.add_report(public_id, message.from_user.id, message.text)
    await _audit(message.from_user.id, "Bot report", public_id)
    await state.clear()
    lang = await _lang(message.from_user.id)
    await message.answer(t(lang, "report_sent"))
    for admin_id in cfg.admin_ids:
        try:
            al = await _lang(admin_id)
            text = t(al, "admin_report_recvd", public_id=public_id) + chr(10)
            text += t(al, "admin_from", user_id=message.from_user.id) + chr(10)
            text += t(al, "admin_reason", reason=message.text)
            await bot.send_message(admin_id, text)
        except Exception:
            pass


async def main():
    sync_task = asyncio.create_task(_sync_dashboard())
    try:
        await dp.start_polling(bot)
    finally:
        sync_task.cancel()
        await asyncio.gather(sync_task, return_exceptions=True)


async def _sync_dashboard():
    if not cfg.dashboard_sync_url or not cfg.dashboard_sync_secret:
        logging.info("Dashboard sync is disabled")
        return
    while True:
        try:
            users = await db._fetchall(
                "SELECT user_id, first_name, last_name, username, language_code, "
                "is_premium, ui_lang, first_seen, last_seen FROM users"
            )
            posts = await db._fetchall(
                "SELECT id, user_id, kind, text, status, public_id, created_at FROM posts"
            )
            user_payload = [
                {key: row[key] for key in row.keys()} for row in users
            ]
            post_payload = [
                {key: row[key] for key in row.keys()} for row in posts
            ]
            payload = json.dumps({
                "users": user_payload,
                "posts": post_payload,
            }).encode("utf-8")
            request = urllib.request.Request(
                cfg.dashboard_sync_url.rstrip("/") + "/api/sync",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "X-Sync-Secret": cfg.dashboard_sync_secret,
                },
                method="POST",
            )
            await asyncio.to_thread(urllib.request.urlopen, request, 10)
        except (OSError, TimeoutError, TypeError, ValueError) as exc:
            logging.warning("Dashboard sync failed: %s", exc)
        await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main())

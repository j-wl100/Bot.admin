import asyncio
import html
import json
import logging
import os
import re
import sqlite3
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from telegram import (
    BotCommand,
    BotCommandScopeAllChatAdministrators,
    BotCommandScopeAllGroupChats,
    ChatPermissions,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.constants import ChatMemberStatus, ChatType, ParseMode
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ==========================================================
# CARGA DE CONFIGURACIÓN EXTERNA (config.json)
# ==========================================================
BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"


def load_config() -> tuple[str, str]:
    data = {}
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ERROR] El archivo config.json tiene un formato invalido: {e}")
            sys.exit(1)

    token = os.getenv("BOT_TOKEN") or data.get("BOT_TOKEN", "")
    db_name = os.getenv("DB_PATH") or data.get("DB_PATH", "admin_bot.db")

    if not token or token == "AQUI_TU_TOKEN_DE_BOTFATHER":
        print("[ERROR] Configura tu BOT_TOKEN en config.json antes de iniciar.")
        sys.exit(1)

    db_path = str(BASE_DIR / db_name)
    return token, db_path


BOT_TOKEN, DB_PATH = load_config()

# Parámetros Anti-Spam / Seguridad
FLOOD_MAX_MESSAGES = 5
FLOOD_TIME_WINDOW = 5      # segundos
FLOOD_MUTE_MINUTES = 5
DUPLICATE_THRESHOLD = 3    # mensajes idénticos seguidos
MAX_TEXT_LENGTH = 1500     # caracteres máximos por mensaje
MAX_MENTIONS_PER_MSG = 5   # menciones máximas por mensaje
CAPTCHA_TIMEOUT = 60       # segundos
ADMIN_CACHE_TTL = 60       # segundos de caché para lista de admins en filtros

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Estructuras en memoria
flood_tracker: dict[tuple[int, int], deque[float]] = defaultdict(
    lambda: deque(maxlen=FLOOD_MAX_MESSAGES + 1)
)
duplicate_tracker: dict[tuple[int, int], deque[str]] = defaultdict(
    lambda: deque(maxlen=DUPLICATE_THRESHOLD)
)
pending_captchas: dict[tuple[int, int], int] = {}
admin_cache: dict[int, tuple[float, set[int]]] = {}

# Patrones de detección
LINK_REGEX = re.compile(r"(https?://\S+|t\.me/\S+|telegram\.me/\S+)", re.IGNORECASE)
MENTION_REGEX = re.compile(r"@\w{3,}")

DANGEROUS_EXTENSIONS = (
    ".apk", ".exe", ".bat", ".cmd", ".msi", ".scr",
    ".vbs", ".ps1", ".sh", ".jar", ".pif", ".com",
)

SENSITIVE_REGEX = re.compile(
    r"\b("
    r"pornhub|xvideos|xnxx|redtube|onlyfans\.com|nudes|packs?\s*xxx|"
    r"gore|zoofilia|cp\s*gratis|caldo\s*de\s*pollo|"
    r"iplogger|grabify|bit\.ly|tinyurl\.com|cutt\.ly"
    r")\b",
    re.IGNORECASE,
)


# ==========================================================
# BASE DE DATOS SQLITE
# ==========================================================
def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS users_cache (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                full_name TEXT,
                updated_at INTEGER
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS warns (
                chat_id INTEGER,
                user_id INTEGER,
                count INTEGER DEFAULT 0,
                reasons TEXT DEFAULT '',
                PRIMARY KEY (chat_id, user_id)
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_settings (
                chat_id INTEGER PRIMARY KEY,
                antilinks INTEGER DEFAULT 1,
                antiflood INTEGER DEFAULT 1,
                antispam INTEGER DEFAULT 1,
                antiforward INTEGER DEFAULT 0,
                antisensible INTEGER DEFAULT 1,
                lockmedia INTEGER DEFAULT 0,
                antiraid INTEGER DEFAULT 0,
                captcha INTEGER DEFAULT 0,
                cleanjoin INTEGER DEFAULT 1,
                autowarn INTEGER DEFAULT 1,
                max_warns INTEGER DEFAULT 3,
                warn_action TEXT DEFAULT 'ban'
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS bad_words (
                chat_id INTEGER,
                word TEXT,
                PRIMARY KEY (chat_id, word)
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS afk_users (
                chat_id INTEGER,
                user_id INTEGER,
                reason TEXT,
                since_ts INTEGER,
                PRIMARY KEY (chat_id, user_id)
            )
            """
        )
        conn.commit()


def ensure_chat_settings(chat_id: int) -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO chat_settings (chat_id) VALUES (?)", (chat_id,))
        conn.commit()
        c.execute("SELECT * FROM chat_settings WHERE chat_id = ?", (chat_id,))
        return dict(c.fetchone())


def update_chat_setting(chat_id: int, field: str, value) -> None:
    ensure_chat_settings(chat_id)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(f"UPDATE chat_settings SET {field} = ? WHERE chat_id = ?", (value, chat_id))
        conn.commit()


def cache_user(user) -> None:
    if not user or user.is_bot:
        return
    username = user.username.lower() if user.username else None
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO users_cache (user_id, username, full_name, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                full_name = excluded.full_name,
                updated_at = excluded.updated_at
            """,
            (user.id, username, user.full_name, int(datetime.now(timezone.utc).timestamp())),
        )
        conn.commit()


def lookup_user_by_username(username: str) -> tuple[int, str] | None:
    clean = username.lstrip("@").lower()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT user_id, full_name FROM users_cache WHERE username = ?", (clean,)
        ).fetchone()
        return (row[0], row[1]) if row else None


def get_bad_words(chat_id: int) -> list[str]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT word FROM bad_words WHERE chat_id = ?", (chat_id,)).fetchall()
        return [r[0] for r in rows]


def get_user_warns(chat_id: int, user_id: int) -> tuple[int, str]:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT count, reasons FROM warns WHERE chat_id = ? AND user_id = ?",
            (chat_id, user_id),
        ).fetchone()
        return (row[0], row[1]) if row else (0, "")


def set_afk(chat_id: int, user_id: int, reason: str) -> None:
    now_ts = int(datetime.now(timezone.utc).timestamp())
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO afk_users (chat_id, user_id, reason, since_ts)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(chat_id, user_id) DO UPDATE SET
                reason = excluded.reason,
                since_ts = excluded.since_ts
            """,
            (chat_id, user_id, reason, now_ts),
        )
        conn.commit()


def get_afk(chat_id: int, user_id: int) -> tuple[str, int] | None:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT reason, since_ts FROM afk_users WHERE chat_id = ? AND user_id = ?",
            (chat_id, user_id),
        ).fetchone()
        return (row[0], row[1]) if row else None


def clear_afk(chat_id: int, user_id: int) -> tuple[str, int] | None:
    data = get_afk(chat_id, user_id)
    if data:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "DELETE FROM afk_users WHERE chat_id = ? AND user_id = ?",
                (chat_id, user_id),
            )
            conn.commit()
    return data


# ==========================================================
# CONTROL DE PERMISOS DE ADMINISTRADOR Y UTILIDADES
# ==========================================================
async def get_group_admin_ids(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> set[int]:
    now = datetime.now(timezone.utc).timestamp()
    cached = admin_cache.get(chat_id)
    if cached and cached[0] > now:
        return cached[1]
    try:
        admins = await context.bot.get_chat_administrators(chat_id)
        ids = {m.user.id for m in admins}
        admin_cache[chat_id] = (now + ADMIN_CACHE_TTL, ids)
        return ids
    except TelegramError:
        return set()


async def is_user_admin(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int) -> bool:
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
        return member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER)
    except TelegramError:
        return False


async def is_sender_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    chat = update.effective_chat
    msg = update.effective_message
    user = update.effective_user
    if not chat or chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return False
    # Administrador anónimo publicando como el propio grupo
    if msg and msg.sender_chat and msg.sender_chat.id == chat.id:
        return True
    if not user:
        return False
    return await is_user_admin(context, chat.id, user.id)


def admin_only(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        chat = update.effective_chat
        if not chat or chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
            if update.effective_message:
                await update.effective_message.reply_text("Comando disponible solo en grupos.")
            return
        if not await is_sender_admin(update, context):
            return  # Ignora silenciosamente a los miembros sin permisos de administrador
        return await func(update, context, *args, **kwargs)

    return wrapper


def group_only(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        chat = update.effective_chat
        if not chat or chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
            await update.effective_message.reply_text("Comando disponible solo en grupos.")
            return
        return await func(update, context, *args, **kwargs)

    return wrapper


async def auto_delete_message(bot, chat_id: int, message_id: int, delay: int = 8) -> None:
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(chat_id=chat_id, message_id=message_id)
    except TelegramError:
        pass


def format_elapsed(since_ts: int) -> str:
    secs = max(1, int(datetime.now(timezone.utc).timestamp()) - since_ts)
    if secs < 60:
        return f"{secs}s"
    mins, secs = divmod(secs, 60)
    if mins < 60:
        return f"{mins}m {secs}s"
    hours, mins = divmod(mins, 60)
    if hours < 24:
        return f"{hours}h {mins}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def parse_duration(token: str) -> timedelta | None:
    match = re.fullmatch(r"(\d+)([smhd])", token.lower())
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2)
    if unit == "s":
        return timedelta(seconds=max(amount, 35))
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    if unit == "d":
        return timedelta(days=amount)
    return None


def resolve_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    args = list(context.args or [])

    if msg.reply_to_message and msg.reply_to_message.from_user:
        u = msg.reply_to_message.from_user
        cache_user(u)
        return u.id, html.escape(u.full_name), args

    for entity in msg.entities or []:
        if entity.type == "text_mention" and entity.user:
            cache_user(entity.user)
            return entity.user.id, html.escape(entity.user.full_name), args[1:] if args else []

    if args:
        first = args[0]
        if first.lstrip("-").isdigit():
            uid = int(first)
            return uid, f"<code>{uid}</code>", args[1:]
        if first.startswith("@"):
            found = lookup_user_by_username(first)
            if found:
                return found[0], html.escape(found[1]), args[1:]

    return None, None, args


async def restore_member_permissions(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int) -> None:
    chat = await context.bot.get_chat(chat_id)
    perms = chat.permissions or ChatPermissions(
        can_send_messages=True,
        can_send_audios=True,
        can_send_documents=True,
        can_send_photos=True,
        can_send_videos=True,
        can_send_video_notes=True,
        can_send_voice_notes=True,
        can_send_polls=True,
        can_send_other_messages=True,
        can_add_web_page_previews=True,
    )
    await context.bot.restrict_chat_member(chat_id=chat_id, user_id=user_id, permissions=perms)


def extract_time_and_reason(args: list[str]) -> tuple[timedelta | None, str]:
    if not args:
        return None, "Sin motivo especificado"
    duration = parse_duration(args[0])
    if duration:
        reason = " ".join(args[1:]).strip() or "Sin motivo especificado"
        return duration, reason
    return None, " ".join(args).strip()


def has_hidden_link(msg) -> bool:
    for entity in (msg.entities or []) + (msg.caption_entities or []):
        if entity.type in ("url", "text_link"):
            return True
    return False


def text_violates_filters(chat_id: int, text: str) -> str | None:
    if not text:
        return None
    if LINK_REGEX.search(text):
        return "enlace"
    if SENSITIVE_REGEX.search(text):
        return "termino sensible"
    lowered = text.lower()
    for w in get_bad_words(chat_id):
        if re.search(rf"\b{re.escape(w)}\b", lowered):
            return "palabra prohibida"
    return None


async def apply_warn_and_check_punishment(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    user_id: int,
    user_name: str,
    reason: str,
    auto_delete_notice: bool = False,
) -> None:
    settings = ensure_chat_settings(chat_id)
    max_warns = settings["max_warns"]
    action = settings["warn_action"]
    fecha = datetime.now().strftime("%d/%m %H:%M")

    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT count, reasons FROM warns WHERE chat_id = ? AND user_id = ?",
            (chat_id, user_id),
        ).fetchone()
        count = (row[0] if row else 0) + 1
        entry = f"- [{fecha}] {reason}"
        reasons = f"{row[1]}\n{entry}".strip() if row and row[1] else entry
        conn.execute(
            """
            INSERT INTO warns (chat_id, user_id, count, reasons) VALUES (?, ?, ?, ?)
            ON CONFLICT(chat_id, user_id) DO UPDATE SET count = ?, reasons = ?
            """,
            (chat_id, user_id, count, reasons, count, reasons),
        )
        conn.commit()

    if count >= max_warns:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM warns WHERE chat_id = ? AND user_id = ?", (chat_id, user_id))
            conn.commit()
        try:
            if action == "ban":
                await context.bot.ban_chat_member(chat_id, user_id)
                act_txt = "baneado permanentemente"
            elif action == "kick":
                await context.bot.ban_chat_member(chat_id, user_id)
                await context.bot.unban_chat_member(chat_id, user_id, only_if_banned=True)
                act_txt = "expulsado"
            else:
                await context.bot.restrict_chat_member(
                    chat_id, user_id, ChatPermissions.no_permissions()
                )
                act_txt = "silenciado"

            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"<b>{user_name}</b> | {count}/{max_warns} advertencias\n"
                    f"Accion: {act_txt}\n"
                    f"Motivo: {html.escape(reason)}"
                ),
                parse_mode=ParseMode.HTML,
            )
        except TelegramError as e:
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"Error aplicando sancion: {e.message}",
            )
    else:
        notice = await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"<b>{user_name}</b> | Advertencia {count}/{max_warns}\n"
                f"Motivo: {html.escape(reason)}"
            ),
            parse_mode=ParseMode.HTML,
        )
        if auto_delete_notice:
            asyncio.create_task(auto_delete_message(context.bot, chat_id, notice.message_id, 10))


# ==========================================================
# COMANDOS EXCLUSIVOS DE ADMINISTRADORES
# ==========================================================
@admin_only
async def cmd_kick(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_id, name, rem_args = resolve_target(update, context)
    if not user_id:
        await update.effective_message.reply_text("Responde a un mensaje o indica ID/@usuario.")
        return
    if user_id == context.bot.id or await is_user_admin(context, chat_id, user_id):
        await update.effective_message.reply_text("No se puede expulsar a un administrador o al bot.")
        return
    reason = " ".join(rem_args).strip() or "Sin motivo especificado"
    try:
        await context.bot.ban_chat_member(chat_id=chat_id, user_id=user_id)
        await context.bot.unban_chat_member(chat_id=chat_id, user_id=user_id, only_if_banned=True)
        await update.effective_message.reply_text(
            f"<b>{name}</b> expulsado.\nMotivo: {html.escape(reason)}",
            parse_mode=ParseMode.HTML,
        )
    except TelegramError as e:
        await update.effective_message.reply_text(f"Error al expulsar: {e.message}")


@admin_only
async def cmd_ban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_id, name, rem_args = resolve_target(update, context)
    if not user_id:
        await update.effective_message.reply_text(
            "Uso: responde a un mensaje o indica ID/@usuario.\nEjemplo: <code>/ban 24h spam</code>",
            parse_mode=ParseMode.HTML,
        )
        return
    if user_id == context.bot.id or await is_user_admin(context, chat_id, user_id):
        await update.effective_message.reply_text("No se puede banear a un administrador o al bot.")
        return

    duration, reason = extract_time_and_reason(rem_args)
    until = datetime.now(timezone.utc) + duration if duration else None
    try:
        await context.bot.ban_chat_member(chat_id=chat_id, user_id=user_id, until_date=until)
        tiempo_txt = rem_args[0] if duration else "permanente"
        await update.effective_message.reply_text(
            f"<b>{name}</b> baneado ({tiempo_txt}).\nMotivo: {html.escape(reason)}",
            parse_mode=ParseMode.HTML,
        )
    except TelegramError as e:
        await update.effective_message.reply_text(f"Error al banear: {e.message}")


@admin_only
async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_id, name, _ = resolve_target(update, context)
    if not user_id:
        await update.effective_message.reply_text("Indica el ID o @usuario a desbanear.")
        return
    try:
        await context.bot.unban_chat_member(chat_id=chat_id, user_id=user_id, only_if_banned=True)
        await update.effective_message.reply_text(f"<b>{name}</b> desbaneado.", parse_mode=ParseMode.HTML)
    except TelegramError as e:
        await update.effective_message.reply_text(f"Error al desbanear: {e.message}")


@admin_only
async def cmd_mute(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_id, name, rem_args = resolve_target(update, context)
    if not user_id:
        await update.effective_message.reply_text(
            "Uso: responde a un mensaje o indica ID/@usuario.\nEjemplo: <code>/mute 30m flood</code>",
            parse_mode=ParseMode.HTML,
        )
        return
    if user_id == context.bot.id or await is_user_admin(context, chat_id, user_id):
        await update.effective_message.reply_text("No se puede silenciar a un administrador o al bot.")
        return

    duration, reason = extract_time_and_reason(rem_args)
    until = datetime.now(timezone.utc) + duration if duration else None
    try:
        await context.bot.restrict_chat_member(
            chat_id=chat_id,
            user_id=user_id,
            permissions=ChatPermissions.no_permissions(),
            until_date=until,
        )
        tiempo_txt = rem_args[0] if duration else "indefinido"
        await update.effective_message.reply_text(
            f"<b>{name}</b> silenciado ({tiempo_txt}).\nMotivo: {html.escape(reason)}",
            parse_mode=ParseMode.HTML,
        )
    except TelegramError as e:
        await update.effective_message.reply_text(f"Error al silenciar: {e.message}")


@admin_only
async def cmd_unmute(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_id, name, _ = resolve_target(update, context)
    if not user_id:
        await update.effective_message.reply_text("Responde a un mensaje o indica ID/@usuario.")
        return
    try:
        await restore_member_permissions(context, chat_id, user_id)
        await update.effective_message.reply_text(f"<b>{name}</b> puede escribir nuevamente.", parse_mode=ParseMode.HTML)
    except TelegramError as e:
        await update.effective_message.reply_text(f"Error: {e.message}")


@admin_only
async def cmd_cerrar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        await context.bot.set_chat_permissions(
            chat_id=update.effective_chat.id,
            permissions=ChatPermissions.no_permissions(),
        )
        await update.effective_message.reply_text(
            "<b>Grupo cerrado</b>\nSolo los administradores pueden enviar mensajes.",
            parse_mode=ParseMode.HTML,
        )
    except TelegramError as e:
        await update.effective_message.reply_text(f"Error al cerrar el grupo: {e.message}")


@admin_only
async def cmd_abrir(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    perms = ChatPermissions(
        can_send_messages=True,
        can_send_audios=True,
        can_send_documents=True,
        can_send_photos=True,
        can_send_videos=True,
        can_send_video_notes=True,
        can_send_voice_notes=True,
        can_send_polls=True,
        can_send_other_messages=True,
        can_add_web_page_previews=True,
        can_invite_users=True,
    )
    try:
        await context.bot.set_chat_permissions(chat_id=update.effective_chat.id, permissions=perms)
        await update.effective_message.reply_text(
            "<b>Grupo abierto</b>\nLos miembros pueden escribir nuevamente.",
            parse_mode=ParseMode.HTML,
        )
    except TelegramError as e:
        await update.effective_message.reply_text(f"Error al abrir el grupo: {e.message}")


@admin_only
async def cmd_warn(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    user_id, name, rem_args = resolve_target(update, context)
    if not user_id:
        await update.effective_message.reply_text("Responde a un usuario o indica ID/@usuario.")
        return
    if user_id == context.bot.id or await is_user_admin(context, chat.id, user_id):
        await update.effective_message.reply_text("No se puede advertir a un administrador o al bot.")
        return
    reason = " ".join(rem_args).strip() or "Incumplimiento de normas"
    await apply_warn_and_check_punishment(context, chat.id, user_id, name, reason)


@admin_only
async def cmd_unwarn(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_id, name, _ = resolve_target(update, context)
    if not user_id:
        await update.effective_message.reply_text("Responde a un usuario o indica ID/@usuario.")
        return
    count, _ = get_user_warns(chat_id, user_id)
    if count <= 0:
        await update.effective_message.reply_text("Sin advertencias registradas.")
        return
    new_count = count - 1
    with sqlite3.connect(DB_PATH) as conn:
        if new_count == 0:
            conn.execute("DELETE FROM warns WHERE chat_id = ? AND user_id = ?", (chat_id, user_id))
        else:
            conn.execute(
                "UPDATE warns SET count = ? WHERE chat_id = ? AND user_id = ?",
                (new_count, chat_id, user_id),
            )
        conn.commit()
    await update.effective_message.reply_text(
        f"<b>{name}</b> | Advertencia retirada. Total: {new_count}",
        parse_mode=ParseMode.HTML,
    )


@admin_only
async def cmd_clearwarns(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_id, name, _ = resolve_target(update, context)
    if not user_id:
        await update.effective_message.reply_text("Responde a un usuario o indica ID/@usuario.")
        return
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM warns WHERE chat_id = ? AND user_id = ?", (chat_id, user_id))
        conn.commit()
    await update.effective_message.reply_text(
        f"<b>{name}</b> | Advertencias reiniciadas a 0.", parse_mode=ParseMode.HTML
    )


@admin_only
async def cmd_warns(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_id, name, _ = resolve_target(update, context)
    if not user_id:
        await update.effective_message.reply_text("Responde a un usuario o indica ID/@usuario.")
        return
    settings = ensure_chat_settings(chat_id)
    count, reasons = get_user_warns(chat_id, user_id)
    motivos = html.escape(reasons) if reasons else "Ninguno"
    await update.effective_message.reply_text(
        f"<b>{name}</b> | {count}/{settings['max_warns']} advertencias\n"
        f"{motivos}",
        parse_mode=ParseMode.HTML,
    )


@admin_only
async def cmd_setwarns(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or not context.args[0].isdigit():
        await update.effective_message.reply_text("Uso: <code>/setwarns 3</code>", parse_mode=ParseMode.HTML)
        return
    val = max(1, min(20, int(context.args[0])))
    update_chat_setting(update.effective_chat.id, "max_warns", val)
    await update.effective_message.reply_text(f"Limite de advertencias: {val}")


@admin_only
async def cmd_warnaction(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or context.args[0].lower() not in ("ban", "mute", "kick"):
        await update.effective_message.reply_text(
            "Uso: <code>/warnaction ban</code> (o <code>mute</code> / <code>kick</code>)",
            parse_mode=ParseMode.HTML,
        )
        return
    action = context.args[0].lower()
    update_chat_setting(update.effective_chat.id, "warn_action", action)
    await update.effective_message.reply_text(f"Sancion al limite: {action}")


@admin_only
async def cmd_info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    user_id, name, _ = resolve_target(update, context)
    if user_id:
        try:
            member = await context.bot.get_chat_member(chat.id, user_id)
            u = member.user
            warns_count, _ = get_user_warns(chat.id, user_id)
            username = f"@{u.username}" if u.username else "Sin username"
            await update.effective_message.reply_text(
                f"<b>Usuario</b>\n"
                f"Nombre: {html.escape(u.full_name)}\n"
                f"Usuario: {username}\n"
                f"ID: <code>{u.id}</code>\n"
                f"Estado: {member.status}\n"
                f"Advertencias: {warns_count}",
                parse_mode=ParseMode.HTML,
            )
        except TelegramError as e:
            await update.effective_message.reply_text(f"Error: {e.message}")
    else:
        count = await context.bot.get_chat_member_count(chat.id)
        await update.effective_message.reply_text(
            f"<b>{html.escape(chat.title)}</b>\n"
            f"ID: <code>{chat.id}</code>\n"
            f"Miembros: {count}",
            parse_mode=ParseMode.HTML,
        )


# ==========================================================
# LIMPIEZA DE MENSAJES
# ==========================================================
@admin_only
async def cmd_del(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    if not msg.reply_to_message:
        await msg.reply_text("Responde al mensaje que deseas borrar.")
        return
    try:
        await msg.reply_to_message.delete()
        await msg.delete()
    except TelegramError as e:
        await msg.reply_text(f"Error al borrar: {e.message}")


@admin_only
async def cmd_purge(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    if not msg.reply_to_message:
        await msg.reply_text("Responde al primer mensaje desde donde quieres limpiar.")
        return
    start_id = msg.reply_to_message.message_id
    end_id = msg.message_id
    if end_id - start_id > 200:
        await msg.reply_text("Maximo por purga: 200 mensajes.")
        return

    ids = list(range(start_id, end_id + 1))
    deleted = 0
    for i in range(0, len(ids), 100):
        chunk = ids[i : i + 100]
        try:
            await context.bot.delete_messages(chat_id=msg.chat_id, message_ids=chunk)
            deleted += len(chunk)
        except TelegramError:
            for mid in chunk:
                try:
                    await context.bot.delete_message(chat_id=msg.chat_id, message_id=mid)
                    deleted += 1
                except TelegramError:
                    pass

    notice = await context.bot.send_message(
        chat_id=msg.chat_id,
        text=f"Limpieza completada ({deleted} mensajes).",
    )
    asyncio.create_task(auto_delete_message(context.bot, msg.chat_id, notice.message_id, 5))


# ==========================================================
# MÓDULOS ANTI-* Y FILTRO DE PALABRAS
# ==========================================================
async def _toggle_setting(update: Update, context: ContextTypes.DEFAULT_TYPE, field: str, label: str) -> None:
    if not context.args or context.args[0].lower() not in ("on", "off"):
        curr = ensure_chat_settings(update.effective_chat.id)[field]
        estado = "ON" if curr else "OFF"
        await update.effective_message.reply_text(
            f"{label}: <b>{estado}</b>\nUso: <code>on</code> / <code>off</code>",
            parse_mode=ParseMode.HTML,
        )
        return
    val = 1 if context.args[0].lower() == "on" else 0
    update_chat_setting(update.effective_chat.id, field, val)
    estado = "ON" if val else "OFF"
    await update.effective_message.reply_text(f"{label}: <b>{estado}</b>", parse_mode=ParseMode.HTML)


@admin_only
async def cmd_antilinks(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle_setting(update, context, "antilinks", "Anti-Enlaces")


@admin_only
async def cmd_antiflood(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle_setting(update, context, "antiflood", "Anti-Flood")


@admin_only
async def cmd_antispam(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle_setting(update, context, "antispam", "Anti-Spam")


@admin_only
async def cmd_antiforward(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle_setting(update, context, "antiforward", "Anti-Reenviados")


@admin_only
async def cmd_antisensible(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle_setting(update, context, "antisensible", "Contenido Delicado")


@admin_only
async def cmd_lockmedia(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle_setting(update, context, "lockmedia", "Bloqueo Multimedia")


@admin_only
async def cmd_antiraid(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle_setting(update, context, "antiraid", "Anti-Raid")


@admin_only
async def cmd_captcha(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle_setting(update, context, "captcha", "Captcha")


@admin_only
async def cmd_cleanjoin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle_setting(update, context, "cleanjoin", "Limpiar entradas/salidas")


@admin_only
async def cmd_autowarn(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _toggle_setting(update, context, "autowarn", "Auto-Warn")


@admin_only
async def cmd_addword(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.effective_message.reply_text("Uso: <code>/addword palabra</code>", parse_mode=ParseMode.HTML)
        return
    word = " ".join(context.args).strip().lower()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO bad_words (chat_id, word) VALUES (?, ?)",
            (update.effective_chat.id, word),
        )
        conn.commit()
    await update.effective_message.reply_text(
        f"Palabra agregada: <code>{html.escape(word)}</code>", parse_mode=ParseMode.HTML
    )


@admin_only
async def cmd_delword(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.effective_message.reply_text("Uso: <code>/delword palabra</code>", parse_mode=ParseMode.HTML)
        return
    word = " ".join(context.args).strip().lower()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "DELETE FROM bad_words WHERE chat_id = ? AND word = ?",
            (update.effective_chat.id, word),
        )
        conn.commit()
    await update.effective_message.reply_text(
        f"Palabra eliminada: <code>{html.escape(word)}</code>", parse_mode=ParseMode.HTML
    )


@admin_only
async def cmd_words(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    words = get_bad_words(update.effective_chat.id)
    if not words:
        await update.effective_message.reply_text("Sin palabras prohibidas configuradas.")
        return
    listado = ", ".join(f"<code>{html.escape(w)}</code>" for w in words)
    await update.effective_message.reply_text(
        f"<b>Palabras prohibidas</b>\n{listado}", parse_mode=ParseMode.HTML
    )


@admin_only
async def cmd_config(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    s = ensure_chat_settings(update.effective_chat.id)
    on_off = lambda v: "ON" if v else "OFF"
    await update.effective_message.reply_text(
        f"<b>Configuracion | {html.escape(update.effective_chat.title)}</b>\n\n"
        f"Anti-Enlaces: {on_off(s['antilinks'])}\n"
        f"Anti-Flood: {on_off(s['antiflood'])}\n"
        f"Anti-Spam: {on_off(s['antispam'])}\n"
        f"Anti-Reenviados: {on_off(s['antiforward'])}\n"
        f"Contenido Delicado: {on_off(s['antisensible'])}\n"
        f"Bloqueo Multimedia: {on_off(s['lockmedia'])}\n"
        f"Anti-Raid: {on_off(s['antiraid'])}\n"
        f"Captcha: {on_off(s['captcha'])}\n"
        f"Limpiar entradas/salidas: {on_off(s['cleanjoin'])}\n"
        f"Auto-Warn: {on_off(s['autowarn'])}\n"
        f"Limite warns: {s['max_warns']} ({s['warn_action']})",
        parse_mode=ParseMode.HTML,
    )


# ==========================================================
# COMANDOS PARA TODOS LOS MIEMBROS
# ==========================================================
@group_only
async def cmd_miswarns(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    chat = update.effective_chat
    cache_user(user)
    settings = ensure_chat_settings(chat.id)
    count, reasons = get_user_warns(chat.id, user.id)

    if count == 0:
        await update.effective_message.reply_text(
            f"<b>{html.escape(user.full_name)}</b> | 0/{settings['max_warns']} advertencias.",
            parse_mode=ParseMode.HTML,
        )
        return

    restantes = max(0, settings["max_warns"] - count)
    await update.effective_message.reply_text(
        f"<b>{html.escape(user.full_name)}</b> | {count}/{settings['max_warns']} advertencias\n"
        f"Restantes para {settings['warn_action']}: {restantes}\n\n"
        f"{html.escape(reasons)}",
        parse_mode=ParseMode.HTML,
    )


@group_only
async def cmd_afk(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    chat = update.effective_chat
    cache_user(user)

    raw_reason = " ".join(context.args).strip() if context.args else "Ocupado"
    if len(raw_reason) > 120:
        raw_reason = raw_reason[:120] + "..."

    if not await is_sender_admin(update, context):
        if has_hidden_link(update.effective_message) or text_violates_filters(chat.id, raw_reason):
            try:
                await update.effective_message.delete()
            except TelegramError:
                pass
            return

    set_afk(chat.id, user.id, raw_reason)
    notice = await update.effective_message.reply_text(
        f"<b>{html.escape(user.full_name)}</b> | AFK\nMotivo: {html.escape(raw_reason)}",
        parse_mode=ParseMode.HTML,
    )
    asyncio.create_task(auto_delete_message(context.bot, chat.id, notice.message_id, 10))


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    is_admin = await is_sender_admin(update, context)
    if not is_admin:
        await update.effective_message.reply_text(
            "<b>Comandos disponibles</b>\n\n"
            "/miswarns — Consultar advertencias propias\n"
            "/afk [motivo] — Activar estado ausente",
            parse_mode=ParseMode.HTML,
        )
        return

    help_text = (
        "<b>Administracion</b>\n\n"
        "<b>Control y Moderacion</b>\n"
        "/cerrar | /abrir\n"
        "/kick [motivo]\n"
        "/ban [tiempo] [motivo] | /unban\n"
        "/mute [tiempo] [motivo] | /unmute\n"
        "/info\n\n"
        "<b>Advertencias</b>\n"
        "/warn [motivo] | /unwarn | /clearwarns | /warns\n"
        "/setwarns &lt;N&gt; | /warnaction &lt;ban|mute|kick&gt;\n"
        "/autowarn &lt;on|off&gt;\n\n"
        "<b>Protecciones (on/off)</b>\n"
        "/antilinks | /antiflood | /antispam\n"
        "/antiforward | /antisensible | /lockmedia\n"
        "/antiraid | /captcha | /cleanjoin\n\n"
        "<b>Filtro y Limpieza</b>\n"
        "/addword | /delword | /words\n"
        "/del | /purge\n"
        "/config\n\n"
        "<b>Miembros</b>\n"
        "/miswarns | /afk"
    )
    await update.effective_message.reply_text(help_text, parse_mode=ParseMode.HTML)


# ==========================================================
# ENTRADAS, SALIDAS Y CAPTCHA
# ==========================================================
async def expire_captcha_task(bot, chat_id: int, user_id: int) -> None:
    await asyncio.sleep(CAPTCHA_TIMEOUT)
    key = (chat_id, user_id)
    if key not in pending_captchas:
        return
    msg_id = pending_captchas.pop(key)
    try:
        await bot.delete_message(chat_id=chat_id, message_id=msg_id)
    except TelegramError:
        pass
    try:
        await bot.ban_chat_member(chat_id=chat_id, user_id=user_id)
        await bot.unban_chat_member(chat_id=chat_id, user_id=user_id, only_if_banned=True)
    except TelegramError:
        pass


async def handle_new_members(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    chat = update.effective_chat
    settings = ensure_chat_settings(chat.id)

    if settings["cleanjoin"]:
        try:
            await msg.delete()
        except TelegramError:
            pass

    admin_ids = await get_group_admin_ids(context, chat.id)

    for member in msg.new_chat_members:
        cache_user(member)
        if member.id == context.bot.id or member.id in admin_ids or member.is_bot:
            continue

        if settings["antiraid"]:
            try:
                await context.bot.ban_chat_member(chat.id, member.id)
                await context.bot.unban_chat_member(chat.id, member.id, only_if_banned=True)
            except TelegramError:
                pass
            continue

        if settings["captcha"]:
            try:
                await context.bot.restrict_chat_member(
                    chat.id, member.id, ChatPermissions.no_permissions()
                )
                kb = InlineKeyboardMarkup(
                    [
                        [
                            InlineKeyboardButton(
                                "Verificar acceso",
                                callback_data=f"captcha:{chat.id}:{member.id}",
                            )
                        ]
                    ]
                )
                mention = f'<a href="tg://user?id={member.id}">{html.escape(member.full_name)}</a>'
                c_msg = await context.bot.send_message(
                    chat_id=chat.id,
                    text=f"{mention} | Verifica tu acceso en {CAPTCHA_TIMEOUT}s.",
                    reply_markup=kb,
                    parse_mode=ParseMode.HTML,
                )
                pending_captchas[(chat.id, member.id)] = c_msg.message_id
                asyncio.create_task(expire_captcha_task(context.bot, chat.id, member.id))
            except TelegramError:
                pass


async def handle_left_member(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    settings = ensure_chat_settings(chat.id)
    if settings["cleanjoin"]:
        try:
            await update.effective_message.delete()
        except TelegramError:
            pass


async def handle_captcha_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    parts = query.data.split(":")
    if len(parts) != 3 or parts[0] != "captcha":
        return

    chat_id = int(parts[1])
    target_user_id = int(parts[2])
    if query.from_user.id != target_user_id:
        await query.answer("Verificacion exclusiva para el usuario nuevo.", show_alert=True)
        return

    pending_captchas.pop((chat_id, target_user_id), None)
    try:
        await restore_member_permissions(context, chat_id, target_user_id)
        await query.answer("Acceso verificado.", show_alert=False)
        await query.message.delete()
    except TelegramError as e:
        await query.answer(f"Error: {e.message}", show_alert=True)


# ==========================================================
# MONITOR AUTOMÁTICO
# ==========================================================
async def handle_infraction(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    reason: str,
    settings: dict,
) -> None:
    msg = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    try:
        await msg.delete()
    except TelegramError:
        pass

    if settings["autowarn"]:
        await apply_warn_and_check_punishment(
            context,
            chat.id,
            user.id,
            html.escape(user.full_name),
            reason,
            auto_delete_notice=True,
        )
    else:
        notice = await context.bot.send_message(
            chat.id,
            f"{html.escape(user.full_name)} | Mensaje eliminado ({html.escape(reason)}).",
        )
        asyncio.create_task(auto_delete_message(context.bot, chat.id, notice.message_id, 8))


async def process_afk_triggers(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    chat = update.effective_chat
    user = update.effective_user

    old_afk = clear_afk(chat.id, user.id)
    if old_afk:
        elapsed = format_elapsed(old_afk[1])
        back_msg = await msg.reply_text(
            f"<b>{html.escape(user.full_name)}</b> | Disponible ({elapsed} AFK).",
            parse_mode=ParseMode.HTML,
        )
        asyncio.create_task(auto_delete_message(context.bot, chat.id, back_msg.message_id, 8))

    notified_ids: set[int] = set()
    if msg.reply_to_message and msg.reply_to_message.from_user:
        target = msg.reply_to_message.from_user
        if target.id != user.id and not target.is_bot:
            afk_data = get_afk(chat.id, target.id)
            if afk_data:
                notified_ids.add(target.id)
                elapsed = format_elapsed(afk_data[1])
                n = await msg.reply_text(
                    f"<b>{html.escape(target.full_name)}</b> | AFK ({elapsed})\n"
                    f"Motivo: {html.escape(afk_data[0])}",
                    parse_mode=ParseMode.HTML,
                )
                asyncio.create_task(auto_delete_message(context.bot, chat.id, n.message_id, 10))

    text_content = msg.text or msg.caption or ""
    for entity in (msg.entities or []) + (msg.caption_entities or []):
        target_id = None
        target_name = None
        if entity.type == "text_mention" and entity.user:
            target_id = entity.user.id
            target_name = entity.user.full_name
        elif entity.type == "mention":
            mention_txt = text_content[entity.offset : entity.offset + entity.length]
            found = lookup_user_by_username(mention_txt)
            if found:
                target_id, target_name = found

        if target_id and target_id != user.id and target_id not in notified_ids:
            afk_data = get_afk(chat.id, target_id)
            if afk_data:
                notified_ids.add(target_id)
                elapsed = format_elapsed(afk_data[1])
                n = await msg.reply_text(
                    f"<b>{html.escape(target_name)}</b> | AFK ({elapsed})\n"
                    f"Motivo: {html.escape(afk_data[0])}",
                    parse_mode=ParseMode.HTML,
                )
                asyncio.create_task(auto_delete_message(context.bot, chat.id, n.message_id, 10))


async def monitor_messages(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.effective_message
    chat = update.effective_chat
    user = update.effective_user

    if not msg or not user:
        return

    cache_user(user)

    if chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return

    # Eximir administradores del grupo (incluyendo anónimos) y canal vinculado
    if msg.sender_chat and msg.sender_chat.id == chat.id:
        return
    if msg.is_automatic_forward:
        return

    admin_ids = await get_group_admin_ids(context, chat.id)
    if user.id in admin_ids:
        await process_afk_triggers(update, context)
        return

    if user.is_bot:
        return

    settings = ensure_chat_settings(chat.id)
    text_content = msg.text or msg.caption or ""

    # 1. Anti-Flood
    if settings["antiflood"]:
        now = datetime.now(timezone.utc).timestamp()
        dq = flood_tracker[(chat.id, user.id)]
        dq.append(now)
        if len(dq) >= FLOOD_MAX_MESSAGES and (now - dq[0]) <= FLOOD_TIME_WINDOW:
            dq.clear()
            try:
                await msg.delete()
                until = datetime.now(timezone.utc) + timedelta(minutes=FLOOD_MUTE_MINUTES)
                await context.bot.restrict_chat_member(
                    chat.id, user.id, ChatPermissions.no_permissions(), until_date=until
                )
                warn_msg = await context.bot.send_message(
                    chat.id,
                    f"<b>{html.escape(user.full_name)}</b> | Silenciado {FLOOD_MUTE_MINUTES}m por flood.",
                    parse_mode=ParseMode.HTML,
                )
                asyncio.create_task(auto_delete_message(context.bot, chat.id, warn_msg.message_id, 8))
            except TelegramError:
                pass
            return

    # 2. Bloqueo de Multimedia
    is_media = bool(
        msg.photo or msg.video or msg.animation or msg.sticker or msg.document or msg.video_note
    )
    if settings["lockmedia"] and is_media:
        await handle_infraction(update, context, "Multimedia bloqueada", settings)
        return

    # 3. Anti-Reenviados
    if settings["antiforward"] and msg.forward_origin is not None:
        await handle_infraction(update, context, "Reenvio no permitido", settings)
        return

    # 4. Contenido Delicado
    if settings["antisensible"]:
        if msg.has_media_spoiler:
            await handle_infraction(update, context, "Spoiler no permitido", settings)
            return
        if msg.document and msg.document.file_name:
            fname = msg.document.file_name.lower()
            if fname.endswith(DANGEROUS_EXTENSIONS):
                await handle_infraction(update, context, f"Archivo bloqueado ({fname})", settings)
                return
        if text_content and SENSITIVE_REGEX.search(text_content):
            await handle_infraction(update, context, "Contenido sensible o acortador", settings)
            return

    # 5. Anti-Enlaces
    if settings["antilinks"]:
        if (text_content and LINK_REGEX.search(text_content)) or has_hidden_link(msg):
            await handle_infraction(update, context, "Enlace no permitido", settings)
            return

    # 6. Anti-Spam
    if settings["antispam"] and text_content:
        if len(text_content) > MAX_TEXT_LENGTH:
            await handle_infraction(update, context, "Mensaje demasiado largo", settings)
            return
        if len(MENTION_REGEX.findall(text_content)) >= MAX_MENTIONS_PER_MSG:
            await handle_infraction(update, context, "Exceso de menciones", settings)
            return
        norm = " ".join(text_content.lower().split())
        if len(norm) >= 4:
            rep_q = duplicate_tracker[(chat.id, user.id)]
            rep_q.append(norm)
            if len(rep_q) == DUPLICATE_THRESHOLD and len(set(rep_q)) == 1:
                rep_q.clear()
                await handle_infraction(update, context, "Mensajes repetidos", settings)
                return

    # 7. Filtro de Palabras Prohibidas
    bad_words = get_bad_words(chat.id)
    if bad_words:
        searchable = text_content.lower()
        if msg.document and msg.document.file_name:
            searchable += " " + msg.document.file_name.lower()
        for w in bad_words:
            if re.search(rf"\b{re.escape(w)}\b", searchable):
                await handle_infraction(update, context, "Palabra prohibida", settings)
                return

    await process_afk_triggers(update, context)


# ==========================================================
# MENÚ DE COMANDOS Y ARRANQUE
# ==========================================================
async def post_init(app: Application) -> None:
    member_commands = [
        BotCommand("miswarns", "Consultar advertencias propias"),
        BotCommand("afk", "Activar estado ausente"),
        BotCommand("help", "Ver comandos disponibles"),
    ]
    admin_commands = [
        BotCommand("cerrar", "Cerrar el chat del grupo"),
        BotCommand("abrir", "Abrir el chat del grupo"),
        BotCommand("kick", "Expulsar usuario"),
        BotCommand("ban", "Banear usuario"),
        BotCommand("unban", "Desbanear usuario"),
        BotCommand("mute", "Silenciar usuario"),
        BotCommand("unmute", "Quitar silencio"),
        BotCommand("warn", "Advertir usuario"),
        BotCommand("unwarn", "Quitar una advertencia"),
        BotCommand("clearwarns", "Reiniciar advertencias"),
        BotCommand("warns", "Ver advertencias de usuario"),
        BotCommand("del", "Borrar mensaje"),
        BotCommand("purge", "Borrar mensajes en bloque"),
        BotCommand("config", "Ver protecciones activas"),
        BotCommand("miswarns", "Consultar advertencias propias"),
        BotCommand("afk", "Activar estado ausente"),
        BotCommand("help", "Ver todos los comandos"),
    ]
    try:
        await app.bot.set_my_commands(member_commands, scope=BotCommandScopeAllGroupChats())
        await app.bot.set_my_commands(admin_commands, scope=BotCommandScopeAllChatAdministrators())
    except TelegramError:
        pass


def main() -> None:
    init_db()
    app = ApplicationBuilder().token(BOT_TOKEN).post_init(post_init).build()

    # Comandos de Administradores
    app.add_handler(CommandHandler("cerrar", cmd_cerrar))
    app.add_handler(CommandHandler("abrir", cmd_abrir))
    app.add_handler(CommandHandler("kick", cmd_kick))
    app.add_handler(CommandHandler("ban", cmd_ban))
    app.add_handler(CommandHandler("unban", cmd_unban))
    app.add_handler(CommandHandler("mute", cmd_mute))
    app.add_handler(CommandHandler("unmute", cmd_unmute))
    app.add_handler(CommandHandler("info", cmd_info))

    app.add_handler(CommandHandler("warn", cmd_warn))
    app.add_handler(CommandHandler("unwarn", cmd_unwarn))
    app.add_handler(CommandHandler("clearwarns", cmd_clearwarns))
    app.add_handler(CommandHandler("warns", cmd_warns))
    app.add_handler(CommandHandler("setwarns", cmd_setwarns))
    app.add_handler(CommandHandler("warnaction", cmd_warnaction))
    app.add_handler(CommandHandler("autowarn", cmd_autowarn))

    app.add_handler(CommandHandler("antilinks", cmd_antilinks))
    app.add_handler(CommandHandler("antiflood", cmd_antiflood))
    app.add_handler(CommandHandler("antispam", cmd_antispam))
    app.add_handler(CommandHandler("antiforward", cmd_antiforward))
    app.add_handler(CommandHandler("antisensible", cmd_antisensible))
    app.add_handler(CommandHandler("lockmedia", cmd_lockmedia))
    app.add_handler(CommandHandler("antiraid", cmd_antiraid))
    app.add_handler(CommandHandler("captcha", cmd_captcha))
    app.add_handler(CommandHandler("cleanjoin", cmd_cleanjoin))

    app.add_handler(CommandHandler("addword", cmd_addword))
    app.add_handler(CommandHandler("delword", cmd_delword))
    app.add_handler(CommandHandler("words", cmd_words))

    app.add_handler(CommandHandler("del", cmd_del))
    app.add_handler(CommandHandler("purge", cmd_purge))
    app.add_handler(CommandHandler("config", cmd_config))

    # Comandos para todos los miembros
    app.add_handler(CommandHandler("miswarns", cmd_miswarns))
    app.add_handler(CommandHandler("afk", cmd_afk))
    app.add_handler(CommandHandler(["help", "start"], cmd_help))

    # Eventos y Captcha
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, handle_new_members))
    app.add_handler(MessageHandler(filters.StatusUpdate.LEFT_CHAT_MEMBER, handle_left_member))
    app.add_handler(CallbackQueryHandler(handle_captcha_callback, pattern=r"^captcha:"))

    # Monitor general de mensajes
    app.add_handler(
        MessageHandler(
            filters.ALL & ~filters.StatusUpdate.ALL & ~filters.COMMAND,
            monitor_messages,
        )
    )

    logger.info("Bot iniciado.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
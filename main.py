import os
import time
import threading
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, ChatPermissions

TOKEN = os.environ.get('ADMIN_TOKEN') or os.environ.get('TELEGRAM_TOKEN') or os.environ.get('TELEGRAM_BOT_TOKEN') or "TU_TOKEN_AQUI"


if TOKEN == "TU_TOKEN_AQUI" or not TOKEN:
    print("❌ ERROR: Debes colocar tu token de Telegram en la variable ADMIN_TOKEN.")
    exit(1)

bot = telebot.TeleBot(TOKEN)
print("SPYCT.ADMIN.BOT encendido y operativo en la red...")

# Bases de datos en memoria
grupos_config = {}
control_spam = {}

def get_grupo_config(chat_id):
    if chat_id not in grupos_config:
        grupos_config[chat_id] = {
            'antilink': False,
            'antinsfw': False,
            'antispam': False,
            'onlyadmin': False,
            'admins_custom': set(),
            'warns_usuarios': {}
        }
    return grupos_config[chat_id]

def verificar_permisos_admin(chat_id, user_id):
    try:
        admins = bot.get_chat_administrators(chat_id)
        es_admin_telegram = any(admin.user.id == user_id for admin in admins)
        cfg = get_grupo_config(chat_id)
        es_admin_custom = user_id in cfg['admins_custom']
        return es_admin_telegram or es_admin_custom
    except Exception:
        return False


# ==========================================
# MENÚ DE ADMINISTRACIÓN
# ==========================================

@bot.message_handler(commands=['menu'])
def cmd_menu(message):
    if message.chat.type == 'private':
        return
    
    menu_texto = """𓄧 𖫰     ֺ   𓄧 𖫰      ֺ   𓄧 𖫰      ֺ   𓄧 𖫰      ֺ   𓄧 

「​㋳」ㅤ𝗦𝗣𝖸Ɔ𝖳-𝗔𝗗𝗠𝗜𝗡,  𝖠𝗊𝗎𝗂 𝗍𝗂𝖾𝗇𝖾𝗌 𝗅𝖺 𝗅𝗂𝗌𝗍𝖺 𝖽𝖾 𝖼𝗈𝗆𝖺𝗇𝖽𝗈𝗌 𝖽𝖾 ᴍᴏᴅᴇʀᴀᴄɪóɴ.

⸻   ֺ   𖫰    !  🔗  ! 𖫰      ֺ   ⸻

#▋         𝗖𝗼𝗺𝗮𝗻𝗱𝗼𝘀.𝗔𝗗𝗠𝗜𝗡       _!?    

%─────────────────
 
   ●   𝖲𝖸𝖲.𝗠𝗢𝗗𝗘𝗥𝗔𝗖𝗜𝗢́𝗡  ⟍  ™

─────────────────

/ban @user
/warn @user [razón]
/unwarn @user
/cerrar
/abrir
/onlyadminon
/onlyadminoff
/antispam 
/antispamoff
/antinsfwon
/antinsfwoff
/antilinkon
/antilinkoff
/chatreset
/config 
/addadmin @user
/deladmin @user
/ping

─────────────────────┘"""
    bot.send_message(message.chat.id, menu_texto)


# ==========================================
# COMANDOS DE ADMINISTRACIÓN MINIMALISTAS
# ==========================================

@bot.message_handler(commands=['ban'])
def cmd_ban(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    if not message.reply_to_message:
        return bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Responde al usuario a banear.")

    try:
        bot.ban_chat_member(message.chat.id, message.reply_to_message.from_user.id)
        bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Usuario sancionado.")
    except Exception:
        bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗘𝗥𝗥𝗢𝗥 ︱ Sin permisos suficientes.")

@bot.message_handler(commands=['onlyadminon'])
def cmd_onlyadminon(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    get_grupo_config(message.chat.id)['onlyadmin'] = True
    try:
        bot.set_chat_permissions(message.chat.id, ChatPermissions(can_send_messages=False))
        bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Modo Administradores activado.")
    except Exception:
        bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗘𝗥𝗥𝗢𝗥 ︱ Requiere permisos de admin.")

@bot.message_handler(commands=['onlyadminoff'])
def cmd_onlyadminoff(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    get_grupo_config(message.chat.id)['onlyadmin'] = False
    try:
        bot.set_chat_permissions(message.chat.id, ChatPermissions(
            can_send_messages=True, can_send_media_messages=True, can_send_other_messages=True, can_add_web_page_previews=True
        ))
        bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Modo Administradores desactivado.")
    except Exception:
        bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗘𝗥𝗥𝗢𝗥 ︱ Requiere permisos de admin.")

@bot.message_handler(commands=['warn'])
def cmd_warn(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    if not message.reply_to_message:
        return bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Responde al usuario.")

    user_id = message.reply_to_message.from_user.id
    parts = message.text.split(maxsplit=1)
    razon = parts[1].strip() if len(parts) > 1 else 'Sin razón especificada'
    cfg = get_grupo_config(message.chat.id)

    if user_id not in cfg['warns_usuarios']:
        cfg['warns_usuarios'][user_id] = 0
    cfg['warns_usuarios'][user_id] += 1

    bot.send_message(message.chat.id, f"𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Advertencia ({cfg['warns_usuarios'][user_id]}/3) ︱ Razón: {razon}")

    if cfg['warns_usuarios'][user_id] >= 3:
        try:
            bot.ban_chat_member(message.chat.id, user_id)
            bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Límite de advertencias alcanzado. Baneado.")
            cfg['warns_usuarios'][user_id] = 0
        except Exception:
            pass

@bot.message_handler(commands=['unwarn'])
def cmd_unwarn(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    if not message.reply_to_message:
        return bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Responde al usuario.")

    get_grupo_config(message.chat.id)['warns_usuarios'][message.reply_to_message.from_user.id] = 0
    bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Advertencias reiniciadas.")

@bot.message_handler(commands=['cerrar'])
def cmd_cerrar(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    try:
        bot.set_chat_permissions(message.chat.id, ChatPermissions(can_send_messages=False))
        bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Chat cerrado.")
    except Exception:
        bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗘𝗥𝗥𝗢𝗥 ︱ Sin permisos.")

@bot.message_handler(commands=['abrir'])
def cmd_abrir(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    try:
        bot.set_chat_permissions(message.chat.id, ChatPermissions(
            can_send_messages=True, can_send_media_messages=True, can_send_other_messages=True, can_add_web_page_previews=True
        ))
        bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Chat abierto.")
    except Exception:
        bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗘𝗥𝗥𝗢𝗥 ︱ Sin permisos.")

@bot.message_handler(commands=['antispam'])
def cmd_antispam(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    get_grupo_config(message.chat.id)['antispam'] = True
    bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Antispam :: ACTIVADO")

@bot.message_handler(commands=['antispamoff'])
def cmd_antispamoff(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    get_grupo_config(message.chat.id)['antispam'] = False
    bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Antispam :: DESACTIVADO")

@bot.message_handler(commands=['antinsfwon'])
def cmd_antinsfwon(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    get_grupo_config(message.chat.id)['antinsfw'] = True
    bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ AntiNSFW :: ACTIVADO")

@bot.message_handler(commands=['antinsfwoff', 'antinstwoff'])
def cmd_antinsfwoff(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    get_grupo_config(message.chat.id)['antinsfw'] = False
    bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ AntiNSFW :: DESACTIVADO")

@bot.message_handler(commands=['antilinkon'])
def cmd_antilinkon(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    get_grupo_config(message.chat.id)['antilink'] = True
    bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Antilink :: ACTIVADO")

@bot.message_handler(commands=['antilinkoff'])
def cmd_antilinkoff(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    get_grupo_config(message.chat.id)['antilink'] = False
    bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Antilink :: DESACTIVADO")

@bot.message_handler(commands=['chatreset'])
def cmd_chatreset(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("Vaciar buffer reciente", callback_data="ejecutar_chatreset"))
    bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗖𝗟𝗘𝗔𝗡 ︱ Limpieza de registro requerida", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data == "ejecutar_chatreset")
def callback_chatreset(call):
    msg = call.message
    if not verificar_permisos_admin(msg.chat.id, call.from_user.id):
        return bot.answer_callback_query(call.id, "Acceso denegado.", show_alert=True)
    
    current_id = msg.message_id
    try:
        for i in range(40):
            try:
                bot.delete_message(msg.chat.id, current_id - i)
            except Exception:
                pass
        bot.answer_callback_query(call.id, "Chat purgado.")
    except Exception:
        bot.answer_callback_query(call.id, "Error en purga.", show_alert=True)

@bot.message_handler(commands=['config'])
def cmd_config(message):
    if message.chat.type == 'private':
        return
    cfg = get_grupo_config(message.chat.id)
    texto = f""". . . ──────────────────────
         𝖲𝖸𝖲.𝗖𝗢𝗡𝗙𝗜𝗚 ︱ 𝗦𝗧𝗔𝗧𝗨𝗦
────────────────────────       

Antilink  :: {'ON' if cfg['antilink'] else 'OFF'}
AntiNSFW  :: {'ON' if cfg['antinsfw'] else 'OFF'}
Antispam  :: {'ON' if cfg['antispam'] else 'OFF'}
OnlyAdmin :: {'ON' if cfg['onlyadmin'] else 'OFF'}"""
    bot.send_message(message.chat.id, texto)

@bot.message_handler(commands=['addadmin'])
def cmd_addadmin(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    if not message.reply_to_message:
        return bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Responde al usuario.")
    
    get_grupo_config(message.chat.id)['admins_custom'].add(message.reply_to_message.from_user.id)
    bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Rango administrativo otorgado.")

@bot.message_handler(commands=['deladmin'])
def cmd_deladmin(message):
    if message.chat.type == 'private':
        return
    if not verificar_permisos_admin(message.chat.id, message.from_user.id):
        return
    if not message.reply_to_message:
        return bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Responde al usuario.")
    
    get_grupo_config(message.chat.id)['admins_custom'].discard(message.reply_to_message.from_user.id)
    bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗔𝗗𝗠𝗜𝗡 ︱ Rango administrativo removido.")

@bot.message_handler(commands=['ping'])
def cmd_ping(message):
    inicio = time.time() * 1000
    sent = bot.send_message(message.chat.id, "𝖲𝖸𝖲.𝗣𝗜𝗡𝗚 ︱ Midiendo...")
    latencia = int((time.time() * 1000) - inicio)
    bot.edit_message_text(f"𝖲𝖸𝖲.𝗣𝗜𝗡𝗚 ︱ Pong :: {latencia} ms", chat_id=message.chat.id, message_id=sent.message_id)


# ==========================================
# FILTROS DE SEGURIDAD AUTOMÁTICA
# ==========================================
@bot.message_handler(func=lambda message: True, content_types=['text'])
def security_filter(message):
    if not message.text or message.chat.type == 'private':
        return
    chat_id = message.chat.id
    user_id = message.from_user.id
    cfg = get_grupo_config(chat_id)

    if verificar_permisos_admin(chat_id, user_id):
        return

    if cfg['antilink']:
        regex_links = r'(https?://[^\s]+|t\.me/[^\s]+|www\.[^\s]+)'
        if re.search(regex_links, message.text, re.IGNORECASE):
            dominios_oficiales = r'(youtube\.com|youtu\.be|tiktok\.com|whatsapp\.com|wa\.me|carrd\.co|google\.com)'
            if not re.search(dominios_oficiales, message.text, re.IGNORECASE):
                try:
                    bot.delete_message(chat_id, message.message_id)
                except Exception:
                    pass
                return

    if cfg['antinsfw']:
        palabras_nsfw = r'\b(porno|nsfw|xxx|desnudo|semen|coger|pene|vagina|orgy)\b'
        if re.search(palabras_nsfw, message.text, re.IGNORECASE):
            try:
                bot.delete_message(chat_id, message.message_id)
            except Exception:
                pass
            return

    if cfg['antispam']:
        ahora = time.time()
        if chat_id not in control_spam:
            control_spam[chat_id] = {}
        if user_id not in control_spam[chat_id]:
            control_spam[chat_id][user_id] = []

        control_spam[chat_id][user_id].append(ahora)
        control_spam[chat_id][user_id] = [t for t in control_spam[chat_id][user_id] if ahora - t < 2.0]

        if len(control_spam[chat_id][user_id]) >= 8:
            try:
                bot.delete_message(chat_id, message.message_id)
                bot.restrict_chat_member(
                    chat_id, user_id,
                    until_date=int(time.time()) + 300,
                    permissions=ChatPermissions(can_send_messages=False)
                )
            except Exception:
                pass
            control_spam[chat_id][user_id] = []


# ==========================================
# SERVIDOR WEB PARA RENDER
# ==========================================
class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'SPYCT.ADMIN.BOT operativo.\n')
    def log_message(self, format, *args):
        pass

def run_server():
    port = int(os.environ.get('PORT', 3001))
    try:
        server = HTTPServer(('0.0.0.0', port), SimpleHandler)
        server.serve_forever()
    except Exception:
        pass

if __name__ == '__main__':
    threading.Thread(target=run_server, daemon=True).start()
    bot.infinity_polling(skip_pending=True, timeout=20)


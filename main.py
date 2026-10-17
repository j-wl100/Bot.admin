import os
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import telebot

# Cargar Token
TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN') or os.environ.get('ADMIN_TOKEN')

if not TOKEN or TOKEN == "TU_TOKEN_AQUI":
    print("❌ ERROR: No se encontró la variable TELEGRAM_BOT_TOKEN en Render.")
    exit(1)

bot = telebot.TeleBot(TOKEN)
print("✅ SPYCT-ADMIN encendido y escuchando...")

# ==========================================
# COMANDO MENÚ ADMIN
# ==========================================
@bot.message_handler(commands=['menu_admin', 'admin'])
def cmd_menu_admin(message):
    print(f"📩 Comando recibido de {message.from_user.username} en chat {message.chat.type}")
    
    if message.chat.type == 'private':
        bot.reply_to(message, "⚠️ Este bot de administración está diseñado para funcionar en GRUPOS.")
        return

    menu_texto = """𓄧 𖫰     ֺ   𓄧 𖫰      ֺ   𓄧 𖫰      ֺ   𓄧 𖫰      ֺ   𓄧 

%──────────────────────────
 
   ●   𝖲𝖸𝖲.𝗠𝗢𝗗𝗘𝗥𝗔𝗖𝗜𝗢́𝗡  ⟍  ™

──────────────────────────�

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

@bot.message_handler(commands=['ping'])
def cmd_ping(message):
    bot.reply_to(message, "𝖲𝖸𝖲.𝗣𝗜𝗡𝗚 ︱ Pong! El bot está activo.")

# ==========================================
# SERVIDOR WEB PARA RENDER (HEALTH CHECK)
# ==========================================
class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'SPYCT ADMIN BOT OK')

def run_server():
    port = int(os.environ.get('PORT', 10000))
    server = HTTPServer(('0.0.0.0', port), SimpleHandler)
    server.serve_forever()

if __name__ == '__main__':
    # Servidor Web
    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    
    # Iniciar Telegram Bot
    bot.infinity_polling(skip_pending=True)

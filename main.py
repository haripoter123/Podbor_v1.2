import subprocess
import sys

# Функция для установки зависимостей
def install_dependencies():
    dependencies = [
        'base58', 'cryptography', 'python-telegram-bot'  # Эти библиотеки нуждаются в установке
    ]
    
    for dep in dependencies:
        try:
            __import__(dep)  # Проверка, установлена ли библиотека
        except ImportError:
            print(f"Устанавливаю {dep}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep])

# Устанавливаем зависимости при запуске
install_dependencies()

# Импорт необходимых библиотек после установки зависимостей
import logging
import os
import random
import hashlib
import base58
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes

# Константы
TARGET_ADDRESS = "TJ5usJLLwjwn7Pw3TPbdzreG7dvgKzfQ5y"
PASSWORD = "Код"
generating = False
attempts = 0
BATCH_SIZE = 1000000  # Устанавливаем размер пакета в 1 000 000
NUM_THREADS = 1
user_data_file = "user_data.txt"
keys_file = "matching_private_keys.txt"
awaiting_custom_batch = False
awaiting_custom_threads = False
message_counter = 0
existing_keys = set()
generated_keys = []

# Настройка логирования
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Загрузка существующих ключей из файла
def load_existing_keys():
    if os.path.exists(keys_file):
        with open(keys_file, "r") as f:
            for line in f:
                if line.startswith("Закрытый ключ:"):
                    key = line.split(": ")[1].strip()
                    existing_keys.add(key)

# Функция для генерации ключей
async def generate_keys(context):
    global attempts, generating, message_counter
    attempts = 0
    last_address = None

    logger.info("Начата генерация ключей.")
    while generating:
        for _ in range(BATCH_SIZE):
            if not generating:
                logger.info("Генерация остановлена.")
                if generated_keys:
                    write_batch_to_file()
                return

            private_key = os.urandom(32)
            private_key_hex = private_key.hex()

            attempts += 1
            generated_address = private_key_to_address(private_key)
            last_address = generated_address
            existing_keys.add(private_key_hex)

            generated_keys.append((private_key_hex, generated_address))

            if generated_address == TARGET_ADDRESS:
                logger.info(f"Найдено совпадение! Закрытый ключ: {private_key_hex} соответствует адресу: {generated_address} после {attempts} попыток.")
                write_batch_to_file()
                return

            if len(generated_keys) >= BATCH_SIZE:
                write_batch_to_file()

            if attempts % BATCH_SIZE == 0:
                message = await context.bot.send_message(chat_id=context.user_data['chat_id'],
                                                         text=f"Сделано попыток: {attempts}, последний адрес: {last_address}")

                if message_counter > 5:
                    await context.bot.delete_message(chat_id=context.user_data['chat_id'],
                                                     message_id=context.user_data['last_message_id'])
                    message_counter -= 1

                context.user_data['last_message_id'] = message.message_id
                message_counter += 1

            if attempts % 100000 == 0:
                logger.info(f"Количество попыток: {attempts}, последний адрес: {last_address}")

def private_key_to_address(private_key):
    sha256 = hashlib.sha256()
    sha256.update(private_key)
    sha256_key = sha256.digest()

    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_key)
    ripemd160_key = ripemd160.digest()

    versioned_key = b'\x41' + ripemd160_key
    checksum = sha256.digest()[:4]
    full_key = versioned_key + checksum
    return base58_encode(full_key)

def base58_encode(input_bytes):
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(input_bytes, 'big')
    result = []

    while num > 0:
        num, rem = divmod(num, 58)
        result.append(ALPHABET[rem])

    for byte in input_bytes:
        if byte == 0:
            result.append('1')
        else:
            break

    return ''.join(reversed(result))

def write_batch_to_file():
    global generated_keys
    with open(keys_file, "a") as f:
        for private_key, address in generated_keys:
            f.write(f"Закрытый ключ: {private_key}\n")
            f.write(f"Адрес: {address}\n")
    logger.info(f"{len(generated_keys)} ключей записано в файл.")
    generated_keys.clear()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.message.from_user.id
    username = update.message.from_user.username
    context.user_data['chat_id'] = update.message.chat_id

    if is_user_registered(user_id):
        keyboard = [
            [InlineKeyboardButton("Начать генерацию", callback_data='start_generation')], 
            [InlineKeyboardButton("Остановить генерацию", callback_data='stop_generation')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Вы уже зарегистрированы! Выберите действие:", reply_markup=reply_markup)
    else:
        keyboard = [[InlineKeyboardButton("Ввести пароль", callback_data='input_password')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Привет, введите пароль для регистрации.", reply_markup=reply_markup)

async def button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global generating, BATCH_SIZE, NUM_THREADS
    query = update.callback_query
    await query.answer()

    if query.data == 'input_password':
        await query.edit_message_text(text="Введите пароль:")

    elif query.data == 'start_generation':
        if generating:
            await query.edit_message_text(text="Генерация уже запущена.")
            return

        generating = True
        await query.edit_message_text(text="Генерация ключей запущена.")

        keyboard = [
            [InlineKeyboardButton("1 000 000", callback_data='set_batch_1000000')], 
            [InlineKeyboardButton("10 000 000", callback_data='set_batch_10000000')], 
            [InlineKeyboardButton("100 000", callback_data='set_batch_100000')], 
            [InlineKeyboardButton("Выбрать свое количество пакетов", callback_data='set_custom_batch')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.message.reply_text("Выберите размер пакета:", reply_markup=reply_markup)

    elif query.data == 'stop_generation':
        generating = False
        await query.edit_message_text(text="Генерация ключей остановлена.")

    elif query.data.startswith('set_batch_'):
        BATCH_SIZE = int(query.data.split('_')[2])
        await query.edit_message_text(text=f"Выбран размер пакета: {BATCH_SIZE}. Выберите количество потоков:")

        keyboard = [
            [InlineKeyboardButton("2", callback_data='set_threads_2')], 
            [InlineKeyboardButton("4", callback_data='set_threads_4')], 
            [InlineKeyboardButton("6", callback_data='set_threads_6')], 
            [InlineKeyboardButton("Выбрать свое количество потоков", callback_data='set_custom_threads')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.message.reply_text("Выберите количество потоков:", reply_markup=reply_markup)

    elif query.data.startswith('set_threads_'):
        NUM_THREADS = int(query.data.split('_')[2])
        await query.edit_message_text(text=f"Выбрано количество потоков: {NUM_THREADS}. Начинаем генерацию.")
        load_existing_keys()
        await generate_keys(context)

async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global generating
    generating = False
    await update.message.reply_text("Генерация ключей остановлена.")

def is_user_registered(user_id):
    if os.path.exists(user_data_file):
        with open(user_data_file, "r") as f:
            for line in f:
                if line.startswith(str(user_id)):
                    return True
    return False

def main():
    application = ApplicationBuilder().token("7601347279:AAE52-5aBoWyy8ijANOJcuiHsMj7kdjBzSs").build()
    load_existing_keys()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("stop", stop))  # Добавляем команду /stop
    application.add_handler(CallbackQueryHandler(button))
    application.run_polling()

if __name__ == "__main__":
    main()

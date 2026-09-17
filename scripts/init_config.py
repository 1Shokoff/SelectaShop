#!/usr/bin/env python3
"""Создаёт рабочий config/selectashop.toml из шаблона.

Генерирует случайный SECRET_KEY и неугадываемый путь админки, ставит
права 0600. Существующий файл не перезаписывается никогда: потерять
рабочий ключ подписи — значит разлогинить всех и сломать все выданные
токены.
"""

from __future__ import annotations

import base64
import secrets
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "config" / "selectashop.example.toml"
TARGET = ROOT / "config" / "selectashop.toml"

# Алфавит без кавычек и обратной косой черты: значение подставляется
# в TOML-строку, и экранирование здесь ни к чему.
SECRET_ALPHABET = string.ascii_letters + string.digits + "!#$%&()*+,-./:;<=>?@[]^_{|}~"


def make_secret_key(length: int = 64) -> str:
    return "".join(secrets.choice(SECRET_ALPHABET) for _ in range(length))


def make_admin_url() -> str:
    token = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(16))
    return f"panel-{token}/"


def make_db_password(length: int = 40) -> str:
    """Пароль роли БД.

    Только буквы и цифры: значение попадает в строку подключения и в
    SQL-команду CREATE ROLE, а экранирование спецсимволов в двух разных
    синтаксисах — лишний источник ошибок при нулевом выигрыше. При длине
    40 символов энтропии более чем достаточно.
    """
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def make_crypto_key() -> str:
    """32 случайных байта в base64 — для AES-256 и HMAC-SHA256."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def main() -> int:
    if TARGET.exists():
        print(f"  {TARGET.relative_to(ROOT)} уже существует — не трогаю.")
        print("  Чтобы пересоздать с нуля, удалите файл вручную.")
        return 0

    if not EXAMPLE.exists():
        print(f"  не найден шаблон {EXAMPLE}", file=sys.stderr)
        return 2

    text = EXAMPLE.read_text(encoding="utf-8")
    text = text.replace('secret_key = ""', f'secret_key = "{make_secret_key()}"', 1)
    text = text.replace(
        'admin_url = "sa-console-CHANGE-ME/"',
        f'admin_url = "{make_admin_url()}"',
        1,
    )

    # Пароли ролей БД. Каждая роль получает свой: компрометация пароля
    # приложения не должна давать прав владельца схемы.
    for key in ("app_password", "owner_password", "backup_password", "superuser_password"):
        text = text.replace(f'{key} = ""', f'{key} = "{make_db_password()}"', 1)

    # Криптографические ключи. Три разных: компрометация перца для поиска
    # не должна позволять расшифровать сами данные.
    for key in ("data_encryption_key", "blind_index_pepper", "token_pepper"):
        text = text.replace(f'{key} = ""', f'{key} = "{make_crypto_key()}"', 1)

    TARGET.write_text(text, encoding="utf-8")
    # 0600: файл содержит ключ подписи сессий и пароль БД. Прочитать его
    # должен уметь только владелец.
    TARGET.chmod(0o600)

    print(f"  создан {TARGET.relative_to(ROOT)} (права 0600)")
    print("  сгенерированы: secret_key, admin_url,")
    print("                 пароли ролей БД (4), криптографические ключи (3)")
    print()
    print("  ОСТАЛОСЬ ЗАПОЛНИТЬ ВРУЧНУЮ:")
    print("    [network].server_ip — публичный IP вашего VPS")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Шифрование персональных данных, слепые индексы и хеширование токенов.

Три разные задачи с тремя разными ключами:

  * шифрование      — AES-256-GCM, обратимо, ключ [security].data_encryption_key
  * слепой индекс   — HMAC-SHA256, необратимо, перец [security].blind_index_pepper
  * хеши токенов    — HMAC-SHA256, необратимо, перец [security].token_pepper

Ключи разделены намеренно. Компрометация перца для поиска даёт лишь
возможность проверить, есть ли в базе конкретный известный адрес, но не
позволяет расшифровать ни одной записи.

Шифрование выполняется на стороне приложения: PostgreSQL никогда не видит
открытый текст, и расширение pgcrypto не требуется.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Длина случайного вектора инициализации для GCM. 96 бит — размер,
# рекомендованный NIST SP 800-38D: при нём не нужно дополнительное
# хеширование значения внутри режима.
NONCE_LENGTH = 12

KEY_LENGTH = 32          # AES-256
PEPPER_LENGTH = 32       # HMAC-SHA256
TOKEN_BYTES = 32         # 256 бит энтропии в ссылках из писем


class DecryptionError(Exception):
    """Не удалось расшифровать: неверный ключ либо повреждённые данные."""


def generate_key() -> str:
    """Новый ключ в base64 — для записи в конфигурационный файл."""
    return base64.b64encode(os.urandom(KEY_LENGTH)).decode("ascii")


def decode_key(value: str, *, name: str, length: int = KEY_LENGTH) -> bytes:
    """Разбирает ключ из конфигурации и проверяет его длину."""
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001 — сообщение важнее типа
        raise ValueError(f"[security].{name} не является корректным base64") from exc
    if len(raw) != length:
        raise ValueError(
            f"[security].{name}: ожидается {length} байт после декодирования, "
            f"получено {len(raw)}"
        )
    return raw


class DataCipher:
    """Шифрование персональных данных.

    Формат хранимого значения: nonce (12 байт) + шифротекст с тегом
    аутентификации. Тег даёт защиту от подмены: изменённую в обход
    приложения строку расшифровать не удастся, а не удастся тихо.
    """

    def __init__(self, key: bytes, key_version: int = 1) -> None:
        if len(key) != KEY_LENGTH:
            raise ValueError(f"ключ шифрования должен быть {KEY_LENGTH} байт")
        self._aead = AESGCM(key)
        self.key_version = key_version

    def encrypt(self, plaintext: str, *, context: bytes) -> bytes:
        """Шифрует строку.

        `context` — связанные данные (AAD). Они не шифруются, но входят в
        расчёт тега. Благодаря этому шифротекст из одного столбца нельзя
        подставить в другой: расшифровка с чужим контекстом провалится.
        """
        nonce = os.urandom(NONCE_LENGTH)
        return nonce + self._aead.encrypt(nonce, plaintext.encode("utf-8"), context)

    def decrypt(self, blob: bytes, *, context: bytes) -> str:
        if len(blob) <= NONCE_LENGTH:
            raise DecryptionError("шифротекст короче минимально возможного")
        nonce, payload = blob[:NONCE_LENGTH], blob[NONCE_LENGTH:]
        try:
            return self._aead.decrypt(nonce, payload, context).decode("utf-8")
        except InvalidTag as exc:
            raise DecryptionError(
                "проверка целостности не прошла: неверный ключ, неверный "
                "контекст или повреждённые данные"
            ) from exc


def blind_index(pepper: bytes, value: str) -> bytes:
    """Детерминированный отпечаток значения для поиска по точному совпадению.

    Нужен потому, что зашифрованный столбец искать нельзя: AES-GCM даёт
    разный шифротекст при каждом вызове. HMAC же от одного значения всегда
    одинаков, поэтому по нему строится обычный уникальный индекс.

    Перец обязателен: без него это был бы просто SHA-256, и адреса из
    утёкшего дампа восстанавливались бы перебором по словарю.
    """
    return hmac.new(pepper, value.encode("utf-8"), hashlib.sha256).digest()


def generate_token() -> str:
    """Случайный токен для ссылки в письме."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(pepper: bytes, token: str) -> bytes:
    """Хеш токена для хранения в базе.

    В базе лежит только хеш: утёкший дамп не позволит подтвердить чужую
    почту или сбросить чужой пароль. Быстрый HMAC здесь уместен —
    энтропию токена задаём мы сами, она составляет 256 бит, и перебор
    невозможен независимо от скорости хеширования.
    """
    return hmac.new(pepper, token.encode("utf-8"), hashlib.sha256).digest()


def constant_time_equals(left: bytes, right: bytes) -> bool:
    """Сравнение без утечки через время выполнения."""
    return hmac.compare_digest(left, right)


def document_hash(text: str) -> bytes:
    """SHA-256 текста юридического документа.

    Фиксируется в записи о согласии. Доказывает согласие не с абстрактной
    «версией 1.0», а ровно с тем текстом, который пользователь видел.
    """
    return hashlib.sha256(text.encode("utf-8")).digest()


# =============================================================================
#  Доступ к ключам из настроек
# =============================================================================
#  Ключи разбираются один раз при первом обращении и кешируются: AESGCM
#  разворачивает ключевое расписание при создании объекта, и делать это
#  на каждый запрос было бы расточительно на единственном ядре.

_cipher_cache: DataCipher | None = None


def get_cipher() -> DataCipher:
    """Шифратор персональных данных, настроенный ключом из конфигурации."""
    global _cipher_cache
    if _cipher_cache is None:
        from django.conf import settings

        _cipher_cache = DataCipher(
            settings.DATA_ENCRYPTION_KEY, settings.ENCRYPTION_KEY_VERSION
        )
    return _cipher_cache


def reset_cipher_cache() -> None:
    """Сбрасывает кеш. Нужен в тестах, где ключ подменяется."""
    global _cipher_cache
    _cipher_cache = None


# Связанные данные для AES-GCM. Привязывают шифротекст к конкретному
# столбцу: перенести значение из одной таблицы в другую не получится.
AAD_USER_EMAIL = b"accounts.UserEmail.email"
AAD_OUTBOX_PAYLOAD = b"notifications.OutboxMessage.payload"

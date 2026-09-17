"""Проверка логинов и адресов электронной почты.

Здесь же нормализация — приведение к каноническому виду, по которому
проверяется уникальность. Правила нормализации менять после появления
пользователей нельзя: изменится набор значений, считающихся одинаковыми.
"""

from __future__ import annotations

import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator

# Латиница, цифры и три разделителя. Кириллица запрещена намеренно:
# «а» кириллическая и «a» латинская неразличимы на вид, и логин «аdmin»
# выглядел бы в точности как «admin».
USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9]*(?:[._-][a-zA-Z0-9]+)*$")

# Символы, которыми подменяют буквы, чтобы обойти список запрещённых имён.
# Свёртка применяется ТОЛЬКО при сверке с зарезервированными именами:
# для обычных логинов она была бы слишком грубой и запретила бы, например,
# совершенно законный «l33t».
CONFUSABLE_FOLD = str.maketrans(
    {
        "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
        "6": "g", "7": "t", "8": "b", "9": "g",
        "@": "a", "$": "s", "!": "i", "|": "i",
    }
)

EMAIL_MAX_LENGTH = 254   # предел длины адреса по RFC 5321


def normalize_username(value: str) -> str:
    """Канонический вид логина: нижний регистр.

    Уникальность проверяется по нему, поэтому IvanPetrov и ivanpetrov —
    один и тот же логин. Исходный регистр сохраняется отдельно и
    используется при отображении.
    """
    return value.strip().lower()


def fold_confusables(value: str) -> str:
    """Свёртка визуально похожих символов — для сверки с чёрным списком."""
    folded = value.lower().translate(CONFUSABLE_FOLD)
    return re.sub(r"[._-]", "", folded)


def validate_username(value: str) -> None:
    """Проверяет логин. Бросает ValidationError с понятным текстом."""
    options = settings.ACCOUNTS
    min_len = options["username_min_length"]
    max_len = options["username_max_length"]

    if len(value) < min_len or len(value) > max_len:
        raise ValidationError(
            f"Логин должен содержать от {min_len} до {max_len} символов."
        )

    if not USERNAME_RE.match(value):
        raise ValidationError(
            "Логин может состоять из латинских букв, цифр и символов «.», "
            "«_», «-». Он должен начинаться с буквы, не может заканчиваться "
            "разделителем и не может содержать два разделителя подряд."
        )

    folded = fold_confusables(value)
    reserved = {fold_confusables(name) for name in options["reserved_usernames"]}
    if folded in reserved:
        # Намеренно не уточняем, что имя именно зарезервировано, а не занято:
        # иначе список служебных имён восстанавливается перебором.
        raise ValidationError("Этот логин недоступен.")


def normalize_email(value: str) -> str:
    """Канонический вид адреса: нижний регистр целиком.

    Точки и «плюс-адресация» НЕ схлопываются по решению владельца проекта:
    one.account@gmail.com и oneaccount@gmail.com считаются разными адресами.
    """
    return value.strip().lower()


def validate_email_address(value: str) -> None:
    if len(value) > EMAIL_MAX_LENGTH:
        raise ValidationError(f"Адрес длиннее {EMAIL_MAX_LENGTH} символов.")

    EmailValidator(message="Введите корректный адрес электронной почты.")(value)

    domain = value.rsplit("@", 1)[-1]
    if domain in settings.ACCOUNTS["blocked_email_domains"]:
        raise ValidationError(
            "Регистрация с одноразовых почтовых сервисов недоступна: "
            "на этот адрес придёт доступ к вашим покупкам."
        )

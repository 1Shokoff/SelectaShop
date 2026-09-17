"""Фильтры журналирования.

Django пишет в журнал путь запроса при любом ответе 4xx и 5xx. Ссылки
подтверждения почты и сброса пароля содержат одноразовый токен прямо в
адресе — и попадают в журнал целиком. Токен живёт часами, поэтому всякий,
кто получил доступ к логам, успел бы подтвердить чужую почту или сменить
чужой пароль.

В nginx такие адреса исключены из журнала доступа условием if=$loggable.
Этот фильтр закрывает вторую половину — журнал самого приложения.
"""

from __future__ import annotations

import logging
import re

# Токен — это 43 символа base64url от 32 байт. Шаблон намеренно шире:
# лучше скрыть лишнее, чем пропустить.
TOKEN_IN_PATH = re.compile(
    r"(/accounts/(?:verify|password-reset)/)[A-Za-z0-9_\-]{16,}"
)
REDACTED = r"\1[токен скрыт]"


def _redact(value):
    if isinstance(value, str):
        return TOKEN_IN_PATH.sub(REDACTED, value)
    return value


class RedactTokens(logging.Filter):
    """Убирает одноразовые токены из сообщений журнала."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _redact(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = {key: _redact(val) for key, val in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(_redact(arg) for arg in record.args)

        return True

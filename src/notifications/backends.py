"""Способы доставки писем.

Два режима, выбираются параметром [email].backend:

  console — письмо печатается в журнал воркера целиком, вместе со ссылкой.
            Позволяет пройти весь сценарий регистрации, не имея ни домена,
            ни учётной записи у провайдера.

  smtp    — отправка через релей.

Собственный почтовый сервер не предусмотрен намеренно: с арендованного IP
письма попадают в спам, а SPF, DKIM и DMARC требуют домена.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage as MimeMessage
from email.utils import formataddr, make_msgid

from django.conf import settings

logger = logging.getLogger(__name__)


class DeliveryError(Exception):
    """Письмо доставить не удалось. Сообщение будет повторено."""


class PermanentDeliveryError(DeliveryError):
    """Повторять бессмысленно: неверный адрес, отказ сервера по существу."""


@dataclass(frozen=True)
class Letter:
    to_address: str
    subject: str
    body: str


def _build_mime(letter: Letter) -> tuple[MimeMessage, str]:
    """Собирает письмо. Русские тема и текст кодируются автоматически."""
    cfg = settings.EMAIL
    message_id = make_msgid(domain=cfg["from_address"].rsplit("@", 1)[-1] or None)

    mime = MimeMessage()
    mime["Subject"] = letter.subject
    mime["From"] = formataddr((cfg["from_name"], cfg["from_address"]))
    mime["To"] = letter.to_address
    mime["Message-ID"] = message_id
    if cfg["reply_to"]:
        mime["Reply-To"] = cfg["reply_to"]

    # Служебные письма не должны порождать автоответы «меня нет в офисе»
    # и не должны попадать в списки рассылок.
    mime["Auto-Submitted"] = "auto-generated"
    mime["X-Auto-Response-Suppress"] = "All"

    mime.set_content(letter.body, subtype="plain", charset="utf-8")
    return mime, message_id


class BaseBackend:
    def send(self, letter: Letter) -> str:
        """Отправляет письмо и возвращает идентификатор сообщения."""
        raise NotImplementedError


class ConsoleBackend(BaseBackend):
    """Печатает письмо в журнал вместо отправки."""

    def send(self, letter: Letter) -> str:
        mime, message_id = _build_mime(letter)
        logger.info(
            "\n"
            "======================= ПИСЬМО (режим console) =======================\n"
            "Кому:  %s\n"
            "Тема:  %s\n"
            "----------------------------------------------------------------------\n"
            "%s\n"
            "======================================================================",
            letter.to_address,
            letter.subject,
            letter.body,
        )
        return message_id


class SmtpBackend(BaseBackend):
    """Отправка через внешний релей."""

    def send(self, letter: Letter) -> str:
        cfg = settings.EMAIL["smtp"]
        mime, message_id = _build_mime(letter)

        # Проверка сертификата релея включена: иначе шифрование канала не
        # защищало бы от подмены сервера, а вместе с ним утекал бы пароль
        # от почтового ящика.
        context = ssl.create_default_context()

        try:
            if cfg["security"] == "ssl":
                server = smtplib.SMTP_SSL(
                    cfg["host"], cfg["port"], timeout=cfg["timeout"], context=context
                )
            else:
                server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=cfg["timeout"])

            with server:
                if cfg["security"] == "tls":
                    server.starttls(context=context)
                if cfg["user"]:
                    server.login(cfg["user"], cfg["password"])
                server.send_message(mime)

        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPNotSupportedError) as exc:
            raise PermanentDeliveryError(str(exc)) from exc
        except smtplib.SMTPAuthenticationError as exc:
            # Отдельная ветка: повторы не помогут, а сообщение об ошибке
            # должно быть узнаваемым. Самая частая причина — использован
            # обычный пароль от ящика вместо пароля приложения.
            raise PermanentDeliveryError(
                f"релей отклонил учётные данные: {exc}. "
                "Проверьте, что в [email.smtp].password указан ПАРОЛЬ ПРИЛОЖЕНИЯ, "
                "а не обычный пароль от почтового ящика."
            ) from exc
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            raise DeliveryError(str(exc)) from exc

        return message_id


def get_backend() -> BaseBackend:
    return {"console": ConsoleBackend, "smtp": SmtpBackend}[settings.EMAIL["backend"]]()

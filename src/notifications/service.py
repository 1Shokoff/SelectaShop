"""Постановка писем в очередь и сборка их текста.

Письмо НЕ отправляется здесь. Создаётся строка в таблице очереди — в той
же транзакции, что и породившее её событие. Отправкой занимается воркер.

Так устроено ради простого свойства: если транзакция регистрации
откатится, письма не будет. И наоборот — если пользователь создан, письмо
гарантированно поставлено в очередь. Внешний брокер такой связки не даёт:
между фиксацией транзакции и публикацией сообщения всегда есть щель.
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.template.loader import render_to_string
from django.utils import timezone

from .backends import Letter
from .models import OutboxMessage, OutboxStatus


class RateLimited(Exception):
    """Слишком много писем на один адрес за короткое время."""


# Письма, которые отправляются ВСЕГДА, в обход лимита частоты.
#
# Лимит существует, чтобы сайт нельзя было использовать для заваливания
# чужого ящика. Но он рассчитан на письма, которые вызывает кто угодно
# анонимным запросом: подтверждение регистрации, сброс пароля, уведомление
# о попытке регистрации.
#
# Уведомление о состоявшейся смене пароля — другое дело. Его порождает
# завершённое действие, а не запрос от неизвестного лица, поэтому
# объёмом оно ограничено самим действием. И это оповещение о захвате
# учётной записи: если его придушить, атакующий, получивший доступ,
# сначала исчерпает квоту запросами сброса, затем сменит пароль — и
# владелец не узнает ничего.
ALWAYS_DELIVER = frozenset({"password_changed"})


def render_letter(template_key: str, context: dict) -> tuple[str, str]:
    """Собирает тему и текст письма из шаблона.

    Первая строка файла — тема, дальше пустая строка и тело. Один файл на
    письмо: тема и текст правятся вместе и не расходятся.
    """
    full_context = {
        "site_name": settings.EMAIL["from_name"],
        "base_url": settings.PUBLIC_BASE_URL,
        **context,
    }
    rendered = render_to_string(f"email/{template_key}.txt", full_context).strip()
    subject, _, body = rendered.partition("\n")
    return subject.strip(), body.strip()


def _too_many_recent(user_email) -> bool:
    """Проверяет лимит писем на один адрес.

    Без него форма восстановления пароля превращается в бесплатный
    инструмент для заваливания чужого ящика: достаточно ввести чужой
    адрес несколько сотен раз.
    """
    limit = settings.ACCOUNTS["max_emails_per_address_per_hour"]
    since = timezone.now() - timedelta(hours=1)
    recent = OutboxMessage.objects.filter(
        recipient_email=user_email, created_at__gte=since
    ).count()
    return recent >= limit


def enqueue(*, user_email, template_key: str, context: dict, ignore_rate_limit: bool = False):
    """Ставит письмо в очередь.

    Вызывать внутри той же транзакции, что и породившее событие.
    """
    if template_key in ALWAYS_DELIVER:
        ignore_rate_limit = True

    if not ignore_rate_limit and _too_many_recent(user_email):
        raise RateLimited(
            f"на этот адрес за час уже отправлено "
            f"{settings.ACCOUNTS['max_emails_per_address_per_hour']} писем"
        )

    subject, body = render_letter(template_key, context)

    message = OutboxMessage(
        recipient_email=user_email,
        template_key=template_key,
        status=OutboxStatus.PENDING,
    )
    # Тело шифруется: внутри лежит ссылка с токеном. Хранить её открытым
    # текстом означало бы обнулить смысл хранения хеша токена — он лежал
    # бы в соседней таблице того же дампа.
    message.set_payload({"subject": subject, "body": body})
    message.save()
    return message


def letter_from(message: OutboxMessage) -> Letter:
    """Разворачивает сообщение очереди в готовое письмо."""
    payload = message.get_payload()
    return Letter(
        to_address=message.recipient_email.address,
        subject=payload.get("subject", ""),
        body=payload.get("body", ""),
    )

"""Определение адреса клиента и защита от перебора.

Счётчики берутся из таблицы событий безопасности: отдельная таблица
счётчиков не нужна, а заодно каждая сработавшая блокировка остаётся
видимой в журнале.
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from .models import SecurityEvent


def client_ip(request) -> str | None:
    """Адрес клиента.

    Берётся из X-Real-IP, который выставляет nginx значением $remote_addr.
    Заголовку можно доверять ровно потому, что до приложения невозможно
    достучаться в обход nginx: порт 8000 не опубликован, а сеть помечена
    internal. Если это когда-нибудь изменится, строку надо пересмотреть
    первой: подделать заголовок тривиально, а на нём висят блокировки.

    REMOTE_ADDR здесь бесполезен — это адрес контейнера nginx.
    """
    value = request.META.get("HTTP_X_REAL_IP") or request.META.get("REMOTE_ADDR")
    if not value:
        return None
    return value.split(",")[0].strip()[:45] or None


def user_agent(request) -> str:
    return request.META.get("HTTP_USER_AGENT", "")[:255]


def record(event_type: str, *, request=None, user=None, **metadata) -> SecurityEvent:
    """Записывает событие безопасности."""
    return SecurityEvent.objects.create(
        user=user,
        event_type=event_type,
        ip=client_ip(request) if request is not None else None,
        user_agent=user_agent(request) if request is not None else "",
        metadata=metadata,
    )


def _count(event_type: str, *, ip=None, user=None, minutes: int) -> int:
    since = timezone.now() - timedelta(minutes=minutes)
    query = SecurityEvent.objects.filter(event_type=event_type, created_at__gte=since)
    if ip is not None:
        query = query.filter(ip=ip)
    if user is not None:
        query = query.filter(user=user)
    return query.count()


def registration_blocked(request) -> bool:
    """Слишком много регистраций с одного адреса за час."""
    ip = client_ip(request)
    if ip is None:
        return False
    limit = settings.ACCOUNTS["max_registrations_per_ip_per_hour"]
    return _count(SecurityEvent.Type.REGISTERED, ip=ip, minutes=60) >= limit


def login_blocked(request, user=None) -> bool:
    """Блокировка после серии неудачных попыток входа.

    Считается и по адресу, и по учётной записи. Только по учётной записи
    было бы недостаточно: перебор идёт по списку логинов, и каждая
    отдельная запись до лимита не дотягивает. Только по адресу — тоже:
    распределённый перебор одной записи прошёл бы мимо счётчика.
    """
    limit = settings.ACCOUNTS["max_login_failures"]
    minutes = settings.ACCOUNTS["login_lockout_minutes"]
    ip = client_ip(request)

    if ip is not None and _count(
        SecurityEvent.Type.LOGIN_FAILED, ip=ip, minutes=minutes
    ) >= limit:
        return True

    if user is not None and _count(
        SecurityEvent.Type.LOGIN_FAILED, user=user, minutes=minutes
    ) >= limit:
        return True

    return False

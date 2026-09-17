"""Общие значения для шаблонов."""

from django.conf import settings


def site(request):
    """Флаги, от которых зависит вёрстка общего каркаса.

    accounts_enabled нужен потому, что маршруты учётных записей
    регистрируются только при наличии базы данных. Без этого флага
    базовый шаблон ссылался бы на несуществующие адреса и падал бы
    при отрисовке главной страницы.
    """
    return {
        "accounts_enabled": settings.DB_AVAILABLE,
        "site_name": settings.EMAIL["from_name"],
    }

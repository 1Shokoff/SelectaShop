"""Корневая карта URL проекта.

Админка подключается только при [django].admin_enabled = true. Пока она
выключена, в приложении физически нет ни одной формы входа — перебирать
нечего.
"""

from django.conf import settings
from django.urls import include, path

urlpatterns = [
    path("", include("core.urls")),
]

# Маршруты учётных записей появляются только вместе с базой данных:
# без неё регистрировать и хранить некого.
if settings.DB_AVAILABLE:
    urlpatterns.append(path("accounts/", include("accounts.urls")))

if settings.ADMIN_ENABLED:
    from django.contrib import admin

    admin.site.site_header = "SelectaShop"
    admin.site.site_title = "SelectaShop"
    admin.site.index_title = "Управление магазином"

    urlpatterns.insert(0, path(settings.ADMIN_URL, admin.site.urls))

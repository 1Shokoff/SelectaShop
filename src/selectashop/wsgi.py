"""Точка входа WSGI. Приложение обслуживается gunicorn."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "selectashop.settings")

application = get_wsgi_application()

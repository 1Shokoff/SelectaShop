"""Конфигурация gunicorn.

Читает тот же единственный файл конфигурации, что и Django, — секция
[gunicorn]. Дублировать параметры в Dockerfile или compose не требуется.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

_path = Path(os.environ.get("SELECTASHOP_CONFIG", "/etc/selectashop/selectashop.toml"))
with _path.open("rb") as _fh:
    _cfg = tomllib.load(_fh).get("gunicorn", {})

# Слушаем все интерфейсы внутри контейнера, но порт не опубликован на хосте
# и сеть помечена internal — снаружи сюда не попасть.
bind = "0.0.0.0:8000"

workers = int(_cfg.get("workers", 2))
threads = int(_cfg.get("threads", 4))

# Потоковый воркер, а не gevent: на одном ядре выигрыш от асинхронности
# незначителен, а monkey-patching усложняет отладку.
worker_class = "gthread"

timeout = int(_cfg.get("timeout", 30))
graceful_timeout = int(_cfg.get("graceful_timeout", 30))
keepalive = int(_cfg.get("keepalive", 5))

# Перезапуск воркера после N запросов — страховка от медленных утечек
# памяти. На 1 GB RAM утечка иначе заканчивается OOM-kill.
max_requests = int(_cfg.get("max_requests", 500))
max_requests_jitter = int(_cfg.get("max_requests_jitter", 50))

# Загрузить приложение до fork(): воркеры делят память через copy-on-write.
preload_app = bool(_cfg.get("preload_app", True))

# Жёсткие лимиты на строку запроса и заголовки. Первый рубеж уже поставлен
# в nginx, это второй — на случай, если до gunicorn когда-нибудь начнут
# ходить напрямую.
limit_request_line = int(_cfg.get("limit_request_line", 4094))
limit_request_fields = int(_cfg.get("limit_request_fields", 100))
limit_request_field_size = int(_cfg.get("limit_request_field_size", 8190))

# Корневая ФС контейнера смонтирована только для чтения, поэтому файлы
# состояния воркеров кладём в /dev/shm (tmpfs, есть всегда).
worker_tmp_dir = "/dev/shm"

accesslog = None          # HTTP-лог ведёт nginx, дублировать незачем
errorlog = "-"            # ошибки в stderr, их забирает docker
loglevel = "info"

# Gunicorn НЕ должен сам интерпретировать заголовки X-Forwarded-*.
# Пустой список источников означает, что ни от кого эти заголовки не
# принимаются на веру. Схему запроса определяет Django через
# SECURE_PROXY_SSL_HEADER — в одном месте, а не в двух.
forwarded_allow_ips = ""

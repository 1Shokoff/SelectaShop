#!/bin/sh
# Точка входа контейнера web.
#
# set -e  — упасть на первой же ошибке, а не стартовать в полуживом виде.
# set -u  — обращение к неустановленной переменной является ошибкой.
set -eu

CONFIG="${SELECTASHOP_CONFIG:-/etc/selectashop/selectashop.toml}"

if [ ! -r "$CONFIG" ]; then
    echo "entrypoint: файл конфигурации $CONFIG недоступен для чтения" >&2
    echo "entrypoint: приложение работает от uid $(id -u)" >&2
    echo "entrypoint:" >&2
    echo "entrypoint: чаще всего причина в правах: файл создаётся с 0600," >&2
    echo "entrypoint: а этому пользователю нужен доступ на чтение." >&2
    echo "entrypoint: на хосте выполните:  make config" >&2
    echo "entrypoint: либо вручную:  chgrp $(id -g) config/selectashop.toml" >&2
    echo "entrypoint:                chmod 0640 config/selectashop.toml" >&2
    exit 78   # EX_CONFIG
fi

# Проверка настроек до запуска воркеров. Лучше не подняться совсем,
# чем подняться с неверной конфигурацией безопасности.
echo "entrypoint: проверка конфигурации Django"
python manage.py check --deploy --fail-level ERROR

# Один образ обслуживает два контейнера: веб-приложение и воркер рассылки.
# Роль передаётся первым аргументом. Собирать и обновлять второй образ ради
# одной другой команды запуска было бы лишней работой.
ROLE="${1:-web}"

if [ "$ROLE" = "worker" ]; then
    # Воркер не применяет миграции и не собирает статику — это делает web.
    # Но стартовать раньше, чем появятся таблицы, он не должен, иначе
    # первые минуты журнал заполняется ошибками о несуществующих таблицах.
    echo "entrypoint: ожидание готовности схемы БД"
    i=0
    while [ "$i" -lt 60 ]; do
        if python manage.py migrate --check >/dev/null 2>&1; then
            break
        fi
        i=$((i + 1))
        sleep 2
    done

    echo "entrypoint: запуск воркера рассылки"
    exec python manage.py send_outbox --loop
fi

# Миграции выполняются ролью-владельцем схемы, а не ролью приложения:
# у последней нет прав DDL, и это намеренно. Роль выбирается алиасом
# подключения admin, описанным в settings.py.
#
# Django берёт блокировку на время миграции, поэтому одновременный запуск
# нескольких экземпляров контейнера безопасен: лишние подождут.
if python -c "
import tomllib, os, sys
p = os.environ.get('SELECTASHOP_CONFIG', '/etc/selectashop/selectashop.toml')
with open(p, 'rb') as fh:
    sys.exit(0 if tomllib.load(fh)['database']['engine'] != 'none' else 1)
"; then
    echo "entrypoint: применение миграций"
    python manage.py migrate --database=admin --noinput
else
    echo "entrypoint: база данных не настроена, миграции пропущены"
fi

# Сборка статики в том, который читает nginx. --clear убирает файлы от
# прошлых сборок: имена хешированные, без очистки том растёт бесконечно.
echo "entrypoint: сборка статики"
python manage.py collectstatic --noinput --clear >/dev/null

echo "entrypoint: запуск gunicorn"
exec gunicorn --config /etc/gunicorn/gunicorn.conf.py selectashop.wsgi:application

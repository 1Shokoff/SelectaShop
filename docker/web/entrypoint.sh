#!/bin/sh
# Точка входа контейнера web.
#
# set -e  — упасть на первой же ошибке, а не стартовать в полуживом виде.
# set -u  — обращение к неустановленной переменной является ошибкой.
set -eu

CONFIG="${SELECTASHOP_CONFIG:-/etc/selectashop/selectashop.toml}"

if [ ! -r "$CONFIG" ]; then
    echo "entrypoint: файл конфигурации $CONFIG недоступен для чтения" >&2
    echo "entrypoint: смонтирован ли config/selectashop.toml в контейнер?" >&2
    exit 78   # EX_CONFIG
fi

# Проверка настроек до запуска воркеров. Лучше не подняться совсем,
# чем подняться с неверной конфигурацией безопасности.
echo "entrypoint: проверка конфигурации Django"
python manage.py check --deploy --fail-level ERROR

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

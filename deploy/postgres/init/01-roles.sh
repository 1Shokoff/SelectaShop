#!/bin/bash
# Создание ролей БД. Выполняется один раз, при первой инициализации кластера.
#
# Смысл разделения ролей прямой: у приложения нет прав DDL, поэтому
# успешная SQL-инъекция не сможет выполнить DROP TABLE, создать функцию
# или прочитать системные таблицы с хешами паролей.
#
# Пароли приходят переменными окружения и в этот файл не попадают —
# скрипт хранится в git.
set -eu

: "${DB_OWNER_USER:?переменная DB_OWNER_USER не задана}"
: "${DB_OWNER_PASSWORD:?переменная DB_OWNER_PASSWORD не задана}"
: "${DB_APP_USER:?переменная DB_APP_USER не задана}"
: "${DB_APP_PASSWORD:?переменная DB_APP_PASSWORD не задана}"
: "${DB_BACKUP_USER:?переменная DB_BACKUP_USER не задана}"
: "${DB_BACKUP_PASSWORD:?переменная DB_BACKUP_PASSWORD не задана}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v owner_user="$DB_OWNER_USER"   -v owner_password="$DB_OWNER_PASSWORD" \
     -v app_user="$DB_APP_USER"       -v app_password="$DB_APP_PASSWORD" \
     -v backup_user="$DB_BACKUP_USER" -v backup_password="$DB_BACKUP_PASSWORD" \
     -v db_name="$POSTGRES_DB" <<-'EOSQL'

    -- ------------------------------------------------------------------
    --  Роли
    -- ------------------------------------------------------------------
    --  owner  — владелец схемы, права DDL. Только миграции.
    --  app    — только DML. Всё обычное обращение приложения.
    --  backup — только чтение. Резервное копирование.
    CREATE ROLE :"owner_user"  LOGIN PASSWORD :'owner_password'  NOSUPERUSER NOCREATEDB NOCREATEROLE;
    CREATE ROLE :"app_user"    LOGIN PASSWORD :'app_password'    NOSUPERUSER NOCREATEDB NOCREATEROLE;
    CREATE ROLE :"backup_user" LOGIN PASSWORD :'backup_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;

    -- ------------------------------------------------------------------
    --  База данных
    -- ------------------------------------------------------------------
    ALTER DATABASE :"db_name" OWNER TO :"owner_user";

    -- Отобрать право подключения у всех и выдать поимённо.
    REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
    GRANT CONNECT ON DATABASE :"db_name" TO :"owner_user", :"app_user", :"backup_user";

    -- ------------------------------------------------------------------
    --  Схема public
    -- ------------------------------------------------------------------
    ALTER SCHEMA public OWNER TO :"owner_user";

    -- Никто, кроме владельца, не может создавать объекты в схеме.
    -- Это прямо блокирует популярный приём: создать функцию или таблицу
    -- через инъекцию и закрепиться в базе.
    REVOKE ALL ON SCHEMA public FROM PUBLIC;
    GRANT USAGE ON SCHEMA public TO :"app_user", :"backup_user";
    GRANT ALL   ON SCHEMA public TO :"owner_user";

    -- ------------------------------------------------------------------
    --  Права на будущие объекты
    -- ------------------------------------------------------------------
    --  Таблицы создаются миграциями от имени owner. Без этих правил
    --  после каждой миграции пришлось бы вручную выдавать права
    --  приложению — и однажды об этом забыли бы.
    ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_user" IN SCHEMA public
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";
    ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_user" IN SCHEMA public
        GRANT USAGE, SELECT ON SEQUENCES TO :"app_user";

    ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_user" IN SCHEMA public
        GRANT SELECT ON TABLES TO :"backup_user";
    ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_user" IN SCHEMA public
        GRANT SELECT ON SEQUENCES TO :"backup_user";

    -- ------------------------------------------------------------------
    --  Ограничения на уровне ролей
    -- ------------------------------------------------------------------
    --  Приложению — жёсткие таймауты: один тяжёлый запрос не должен
    --  занять единственное ядро сервера.
    ALTER ROLE :"app_user" SET statement_timeout = '15s';
    ALTER ROLE :"app_user" SET idle_in_transaction_session_timeout = '30s';

    --  Миграциям таймаут снимается: создание индекса на большой таблице
    --  законно длится дольше, и убивать его на середине нельзя.
    ALTER ROLE :"owner_user" SET statement_timeout = '0';
    ALTER ROLE :"owner_user" SET idle_in_transaction_session_timeout = '0';

    --  Роль резервного копирования физически не может ничего изменить.
    ALTER ROLE :"backup_user" SET default_transaction_read_only = on;
    ALTER ROLE :"backup_user" SET statement_timeout = '0';

EOSQL

echo "01-roles.sh: роли ${DB_OWNER_USER}, ${DB_APP_USER}, ${DB_BACKUP_USER} созданы"

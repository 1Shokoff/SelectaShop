#!/bin/sh
# Сертификат для шифрования канала между приложением и базой данных.
#
# Имя в сертификате — db, то есть имя контейнера во внутренней сети docker.
# Приложение подключается в режиме verify-full: проверяется и подпись, и
# совпадение имени хоста. Более слабые режимы (require, prefer) шифруют
# канал, но не защищают от подмены сервера — то есть не дают главного.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="$ROOT/deploy/generated/certs/db"

# uid пользователя postgres в официальном образе.
PG_UID=999
PG_GID=999

mkdir -p "$CERT_DIR"

openssl req -x509 -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 3650 \
    -subj "/CN=db" \
    -addext "subjectAltName=DNS:db" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    2>/dev/null

# Сертификат читают оба контейнера — он не секретен.
chmod 0644 "$CERT_DIR/server.crt"

# Приватный ключ PostgreSQL проверяет сам: он ОТКАЖЕТСЯ стартовать, если
# у файла есть права для группы или для всех. Владельцем должен быть
# пользователь, от которого работает сервер.
if chown "$PG_UID:$PG_GID" "$CERT_DIR/server.key" 2>/dev/null; then
    chmod 0600 "$CERT_DIR/server.key"
    echo "  сертификат БД создан: deploy/generated/certs/db/ (CN=db, 10 лет)"
    echo "  ключ: владелец $PG_UID:$PG_GID, права 0600"
else
    chmod 0600 "$CERT_DIR/server.key"
    echo "  ВНИМАНИЕ: не удалось сменить владельца ключа (нужен root)." >&2
    echo "  PostgreSQL не сможет его прочитать. Выполните от root:" >&2
    echo "    chown $PG_UID:$PG_GID deploy/generated/certs/db/server.key" >&2
    echo "    chmod 0600 deploy/generated/certs/db/server.key" >&2
    exit 1
fi

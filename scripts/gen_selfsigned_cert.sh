#!/bin/sh
# Самоподписанный сертификат для работы по IP-адресу без домена.
#
# Браузер покажет предупреждение — доверенного центра сертификации за
# таким сертификатом нет. Но трафик будет зашифрован, а это разница
# между «пароль виден любому узлу на маршруте» и «не виден».
#
# Когда появится домен, замените на Let's Encrypt.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$ROOT/config/selectashop.toml"
CERT_DIR="$ROOT/deploy/generated/certs"

if [ ! -r "$CONFIG" ]; then
    echo "не найден $CONFIG — выполните: make init-config" >&2
    exit 78
fi

# IP берём из единственного конфига, чтобы он не разъехался с nginx.
SERVER_IP="$(python3 -c "
import tomllib, sys
with open('$CONFIG','rb') as fh:
    print(tomllib.load(fh)['network']['server_ip'])
")"

mkdir -p "$CERT_DIR"

# subjectAltName с IP обязателен: браузеры давно игнорируют CN.
# Без SAN сертификат не примет ни один современный клиент.
openssl req -x509 -nodes \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 825 \
    -subj "/CN=$SERVER_IP" \
    -addext "subjectAltName=IP:$SERVER_IP" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    2>/dev/null

chmod 0644 "$CERT_DIR/server.crt"

# Приватный ключ читает nginx, работающий в контейнере от uid 101.
# Пространства пользователей не используется, поэтому uid на хосте и в
# контейнере совпадают: отдаём ключ группе 101 и закрываем от всех
# остальных. Права 0644 на приватный ключ были бы ошибкой — его смог бы
# прочитать любой пользователь хоста.
if chown 0:101 "$CERT_DIR/server.key" 2>/dev/null; then
    chmod 0640 "$CERT_DIR/server.key"
else
    chmod 0600 "$CERT_DIR/server.key"
    echo "  ВНИМАНИЕ: не удалось сменить группу ключа (нужен root)." >&2
    echo "  Ключ закрыт правами 0600 и nginx его не прочитает." >&2
    echo "  Выполните от root: chown 0:101 deploy/generated/certs/server.key" >&2
    echo "                     chmod 0640 deploy/generated/certs/server.key" >&2
fi

echo "  сертификат создан: deploy/generated/certs/ (CN=$SERVER_IP, 825 дней)"
echo
echo "  ДАЛЬШЕ: в config/selectashop.toml установите [tls].enabled = true,"
echo "  затем выполните: make config && make restart"

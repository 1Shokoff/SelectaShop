#!/bin/sh
# Самоподписанный сертификат сайта для работы по IP-адресу без домена.
#
# Браузер покажет предупреждение — доверенного центра сертификации за
# таким сертификатом нет. Но трафик будет зашифрован, а это разница
# между «пароль виден любому узлу на маршруте» и «не виден».
#
# Когда появится домен, замените на Let's Encrypt.
#
# Скрипт можно запускать сколько угодно раз: прошлая пара удаляется, и
# выпускается новая. Для смены владельца ключа нужен root — если вы не
# root, скрипт воспользуется sudo и может спросить пароль.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/cert_lib.sh"

CONFIG="$ROOT/config/selectashop.toml"
CERT_DIR="$ROOT/deploy/generated/certs"

# uid и gid пользователя nginx в образе nginx-unprivileged.
NGINX_UID=101

if [ ! -r "$CONFIG" ]; then
    echo "не найден $CONFIG — выполните: make init-config" >&2
    exit 78
fi

# IP берём из единственного конфига, чтобы он не разъехался с nginx.
SERVER_IP="$(python3 -c "
import tomllib
with open('$CONFIG','rb') as fh:
    print(tomllib.load(fh)['network']['server_ip'])
")"

prepare_cert_dir "$CERT_DIR"

# subjectAltName с IP обязателен: браузеры давно игнорируют CN.
# Без SAN сертификат не примет ни один современный клиент.
issue_certificate "$CERT_DIR" "$SERVER_IP" "IP:$SERVER_IP" 825

# Сертификат не секретен, его читают все.
chmod 0644 "$CERT_DIR/server.crt"

# Ключ отдаётся группе nginx и закрывается от остальных. Права 0644 на
# приватный ключ были бы ошибкой — его прочитал бы любой пользователь хоста.
secure_private_key "$CERT_DIR/server.key" 0 "$NGINX_UID" 0640 "nginx"

echo "  сертификат сайта создан: deploy/generated/certs/ (CN=$SERVER_IP, 825 дней)"
echo "  ключ: владелец root:$NGINX_UID, права 0640"
echo
echo "  ДАЛЬШЕ: в config/selectashop.toml установите [tls].enabled = true,"
echo "  затем выполните: make config"

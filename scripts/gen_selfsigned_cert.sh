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

# Адреса берём из единственного конфига, чтобы они не разъехались с nginx.
SERVER_IP="$(python3 -c "
import tomllib
with open('$CONFIG','rb') as fh:
    print(tomllib.load(fh)['network']['server_ip'])
")"

# В SAN попадает и IP, и все имена из extra_allowed_hosts.
#
# Имена здесь не роскошь. Браузер, обращаясь к голому IP-адресу, НЕ
# отправляет SNI — стандарт прямо запрещает писать туда IP. Соединение
# без SNI выглядит нетипично: его отбрасывает часть фильтрующего
# оборудования, и в браузере это выглядит как обрыв рукопожатия.
#
# Достаточно любого имени, даже прописанного только в hosts на своей
# машине: браузер начнёт отправлять SNI. Тот же механизм пригодится и
# при переходе на настоящий домен — его тоже достаточно вписать в
# extra_allowed_hosts.
SAN="$(python3 -c "
import tomllib
with open('$CONFIG','rb') as fh:
    net = tomllib.load(fh)['network']
parts = ['IP:' + net['server_ip']]
parts += ['DNS:' + h for h in net.get('extra_allowed_hosts', []) if h]
print(','.join(parts))
")"

prepare_cert_dir "$CERT_DIR"

# subjectAltName обязателен: браузеры давно игнорируют CN.
# Без SAN сертификат не примет ни один современный клиент.
issue_certificate "$CERT_DIR" "$SERVER_IP" "$SAN" 825

# Сертификат не секретен, его читают все.
chmod 0644 "$CERT_DIR/server.crt"

# Ключ отдаётся группе nginx и закрывается от остальных. Права 0644 на
# приватный ключ были бы ошибкой — его прочитал бы любой пользователь хоста.
secure_private_key "$CERT_DIR/server.key" 0 "$NGINX_UID" 0640 "nginx"

echo "  сертификат сайта создан: deploy/generated/certs/ (825 дней)"
echo "  имена в сертификате: $SAN"
echo "  ключ: владелец root:$NGINX_UID, права 0640"
echo
echo "  ДАЛЬШЕ: в config/selectashop.toml установите [tls].enabled = true,"
echo "  затем выполните: make config"

# Общие операции выпуска самоподписанных сертификатов.
# Подключается из gen_selfsigned_cert.sh и gen_db_cert.sh.
#
# Ключи должны принадлежать пользователю, от которого работает процесс
# ВНУТРИ контейнера (nginx — uid 101, PostgreSQL — uid 999). Пространства
# пользователей не используется, поэтому uid на хосте и в контейнере
# совпадают, и владельца приходится менять — а это требует root.

# Выполняет команду с правами root:
#   уже root  — напрямую;
#   есть sudo — через sudo (может спросить пароль);
#   иначе     — возвращает 1.
run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        return 1
    fi
}

# Готовит каталог и удаляет прошлую пару файлов.
#
# Удаление обязательно, а не «на всякий случай». После первого выпуска
# ключ принадлежит root, и обычный пользователь перезаписать его не может.
# Зато удалить может: право на удаление файла даёт каталог, а не сам файл.
# Без этого шага повторный запуск падал с «Permission denied».
prepare_cert_dir() {
    _dir="$1"
    mkdir -p "$_dir" 2>/dev/null || run_as_root mkdir -p "$_dir" || return 1
    rm -f "$_dir/server.key" "$_dir/server.crt" 2>/dev/null \
        || run_as_root rm -f "$_dir/server.key" "$_dir/server.crt" \
        || return 1
}

# Выпускает самоподписанный сертификат.
#
# Вывод openssl НЕ подавляется полностью: он пишет и точки прогресса, и
# сообщения об ошибках в один поток. Раньше весь поток уходил в /dev/null,
# и при отказе человек видел только код возврата — без единой подсказки,
# что именно пошло не так.
issue_certificate() {
    _dir="$1"
    _cn="$2"
    _san="$3"
    _days="$4"

    _log="$(mktemp)"
    if openssl req -x509 -nodes \
            -newkey rsa:2048 \
            -keyout "$_dir/server.key" \
            -out "$_dir/server.crt" \
            -days "$_days" \
            -subj "/CN=$_cn" \
            -addext "subjectAltName=$_san" \
            -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
            -addext "extendedKeyUsage=serverAuth" \
            2>"$_log"; then
        rm -f "$_log"
        return 0
    fi

    echo "  openssl не смог выпустить сертификат:" >&2
    grep -vE '^[.+*]*$' "$_log" | sed 's/^/    /' >&2
    rm -f "$_log"
    return 1
}

# Ставит владельца и права на приватный ключ.
# При неудаче печатает точные команды и возвращает 1.
secure_private_key() {
    _file="$1"
    _owner="$2"
    _group="$3"
    _mode="$4"
    _reader="$5"

    if run_as_root chown "$_owner:$_group" "$_file" \
       && run_as_root chmod "$_mode" "$_file"; then
        return 0
    fi

    chmod 0600 "$_file" 2>/dev/null || true

    {
        echo
        echo "  Не удалось сменить владельца приватного ключа."
        echo "  Нужны права root, а sudo недоступен."
        echo
        echo "  Ключ должен читаться процессом $_reader внутри контейнера."
        echo "  Выполните от root:"
        echo "      chown $_owner:$_group $_file"
        echo "      chmod $_mode $_file"
        echo
        echo "  После этого ПОВТОРНО запускать выпуск не нужно —"
        echo "  сертификат и ключ уже созданы и пригодны."
    } >&2
    return 1
}

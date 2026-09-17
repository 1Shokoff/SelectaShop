#!/usr/bin/env python3
"""Генератор конфигурации SelectaShop.

Читает единственный источник правды -- config/selectashop.toml -- и порождает:

  deploy/generated/nginx.conf                 конфиг nginx
  deploy/generated/.env                       переменные для docker compose
  deploy/generated/docker-compose.egress.yml  оверлей сети (если разрешён egress)

Скрипт намеренно обходится стандартной библиотекой: на VPS с 1 GB RAM
не нужен лишний слой зависимостей ради подстановки строк.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import shutil
import stat
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config" / "selectashop.toml"
EXAMPLE = ROOT / "config" / "selectashop.example.toml"
TEMPLATE = ROOT / "deploy" / "nginx" / "nginx.conf.template"
SERVER_BODY = ROOT / "deploy" / "nginx" / "server_body.template"
OUT_DIR = ROOT / "deploy" / "generated"

MIN_SECRET_KEY_LEN = 50

# Значения из .example, которые обязаны быть изменены перед запуском.
PLACEHOLDERS = {
    ("network", "server_ip"): "203.0.113.10",
    ("django", "admin_url"): "sa-console-CHANGE-ME/",
}


class ConfigError(Exception):
    """Конфигурация не пригодна к использованию."""


def load() -> dict:
    if not CONFIG.exists():
        raise ConfigError(
            f"не найден {CONFIG.relative_to(ROOT)}\n"
            f"  создайте его командой:  make init-config"
        )
    with CONFIG.open("rb") as fh:
        return tomllib.load(fh)


def get(cfg: dict, section: str, key: str, default=None):
    try:
        return cfg[section][key]
    except KeyError:
        if default is not None:
            return default
        raise ConfigError(f"отсутствует обязательный параметр [{section}].{key}")


def validate(cfg: dict) -> list[str]:
    """Проверки, отказывающие в запуске (ошибки) и предупреждения."""
    warnings: list[str] = []

    secret = get(cfg, "django", "secret_key", "")
    if not secret or len(secret) < MIN_SECRET_KEY_LEN:
        raise ConfigError(
            "[django].secret_key пуст или короче "
            f"{MIN_SECRET_KEY_LEN} символов.\n"
            "  сгенерируйте новый:  make secret"
        )
    if secret.startswith("django-insecure"):
        raise ConfigError(
            "[django].secret_key содержит префикс django-insecure — "
            "это ключ из шаблона, он не секретен."
        )

    ip = get(cfg, "network", "server_ip")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ConfigError(f"[network].server_ip = {ip!r} не является IP-адресом")

    for (section, key), placeholder in PLACEHOLDERS.items():
        if cfg.get(section, {}).get(key) == placeholder:
            raise ConfigError(
                f"[{section}].{key} осталось значением-заглушкой {placeholder!r}. "
                "Замените его."
            )

    if get(cfg, "django", "debug", False):
        warnings.append(
            "DEBUG = true. На сервере, доступном из интернета, это утечка "
            "трассировок со значениями переменных, включая пароли."
        )

    tls_on = get(cfg, "tls", "enabled", False)
    if not tls_on:
        warnings.append(
            "TLS выключен. Трафик идёт открытым текстом. Это допустимо, пока "
            "на сайте нет форм входа, но ОБЯЗАТЕЛЬНО к включению до этапа 1."
        )
        if get(cfg, "django", "admin_enabled", False):
            raise ConfigError(
                "[django].admin_enabled = true при выключенном TLS. "
                "Пароль администратора ушёл бы по сети открытым текстом. "
                "Включите [tls].enabled или выключите админку."
            )
    if tls_on and get(cfg, "tls", "hsts_seconds", 0) > 0:
        warnings.append(
            "HSTS включён. Убедитесь, что сертификат доверенный: браузер "
            "запомнит требование HTTPS и откат на HTTP потребует чистки "
            "состояния у каждого посетителя."
        )

    engine = get(cfg, "database", "engine", "none")
    if engine not in {"none", "sqlite", "postgresql"}:
        raise ConfigError(f"[database].engine = {engine!r}; ожидается none|sqlite|postgresql")
    if engine == "sqlite":
        warnings.append("[database].engine = sqlite — не для продакшена.")

    if engine == "postgresql":
        db = cfg["database"]
        for key in ("app_password", "owner_password", "backup_password", "superuser_password"):
            if not db.get(key):
                raise ConfigError(
                    f"[database].{key} пуст. Сгенерируйте пароли: make init-config"
                )
        passwords = [db[k] for k in
                     ("app_password", "owner_password", "backup_password", "superuser_password")]
        if len(set(passwords)) != len(passwords):
            raise ConfigError(
                "Пароли ролей БД совпадают между собой. Смысл разделения ролей "
                "в том, что компрометация одной не даёт прав другой."
            )

        # Криптографические ключи. Проверяются здесь, а не только при старте
        # Django: ошибка должна обнаружиться до запуска контейнеров.
        sec = cfg.get("security", {})
        keys = {}
        for name in ("data_encryption_key", "blind_index_pepper", "token_pepper"):
            value = sec.get(name, "")
            if not value:
                raise ConfigError(
                    f"[security].{name} пуст. Сгенерируйте: make init-config"
                )
            try:
                raw = base64.b64decode(value, validate=True)
            except Exception as exc:
                raise ConfigError(f"[security].{name} не является корректным base64") from exc
            if len(raw) != 32:
                raise ConfigError(
                    f"[security].{name}: ожидается 32 байта, получено {len(raw)}"
                )
            keys[name] = raw
        if len(set(keys.values())) != 3:
            raise ConfigError(
                "Криптографические ключи в [security] совпадают между собой. "
                "Они должны быть разными: компрометация перца для поиска не "
                "должна позволять расшифровать данные."
            )

        if db.get("tls_enabled", False):
            key_path = ROOT / "deploy" / "generated" / "certs" / "db" / "server.key"
            if not key_path.exists():
                raise ConfigError(
                    "[database].tls_enabled = true, но сертификат БД не создан.\n"
                    "  выполните:  make db-cert"
                )
        else:
            warnings.append(
                "[database].tls_enabled = false — канал до БД не шифруется."
            )

    for name in ("edge_subnet", "internal_subnet", "data_subnet"):
        value = get(cfg, "network", name)
        try:
            ipaddress.ip_network(value)
        except ValueError:
            raise ConfigError(f"[network].{name} = {value!r} не является подсетью")

    if get(cfg, "network", "web_egress", False):
        warnings.append(
            "[network].web_egress = true — контейнер web получает доступ в "
            "интернет. Это расширяет ущерб от возможного RCE."
        )

    methods = get(cfg, "nginx", "allowed_methods", ["GET", "HEAD"])
    unknown = set(methods) - {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
    if unknown:
        raise ConfigError(f"[nginx].allowed_methods содержит неизвестные методы: {unknown}")

    return warnings


# --------------------------------------------------------------------------
# Сборка блоков nginx
# --------------------------------------------------------------------------

def _header_pairs(cfg: dict) -> list[tuple[str, str]]:
    """Единый список заголовков безопасности.

    Из него порождаются и add_header, и proxy_hide_header, поэтому
    списки физически не могут разъехаться.
    """
    sec = cfg.get("security", {})
    return [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", sec.get("x_frame_options", "DENY")),
        ("Referrer-Policy", sec.get("referrer_policy", "same-origin")),
        ("Content-Security-Policy", sec.get("content_security_policy", "default-src 'self'")),
        ("Permissions-Policy", sec.get("permissions_policy", "")),
        ("Cross-Origin-Opener-Policy", sec.get("cross_origin_opener_policy", "same-origin")),
        ("Cross-Origin-Resource-Policy", sec.get("cross_origin_resource_policy", "same-origin")),
        ("X-Permitted-Cross-Domain-Policies", "none"),
    ]


def build_proxy_hide_headers(cfg: dict) -> str:
    """Скрывает заголовки безопасности, пришедшие от Django.

    Django выставляет часть этих заголовков сам (SecurityMiddleware,
    XFrameOptionsMiddleware). Если их не убрать, клиент получит каждый
    заголовок дважды. Для X-Frame-Options это не косметика: при нескольких
    экземплярах заголовка часть браузеров считает его некорректным и
    перестаёт применять защиту от фрейминга вовсе.

    Настройки Django при этом намеренно остаются включёнными: если
    приложение когда-нибудь окажется доступно в обход nginx, оно защитит
    себя само.
    """
    lines = [f"        proxy_hide_header {name};" for name, _ in _header_pairs(cfg)]
    lines.append("        proxy_hide_header Strict-Transport-Security;")
    return "\n".join(lines)


def build_security_headers(cfg: dict, indent: str = "    ") -> str:
    tls = cfg.get("tls", {})
    lines = [
        f'{indent}add_header {name} "{value}" always;'
        for name, value in _header_pairs(cfg)
        if value
    ]

    if tls.get("enabled") and tls.get("hsts_seconds", 0) > 0:
        hsts = f"max-age={tls['hsts_seconds']}"
        if tls.get("hsts_include_subdomains"):
            hsts += "; includeSubDomains"
        if tls.get("hsts_preload"):
            hsts += "; preload"
        lines.append(f'{indent}add_header Strict-Transport-Security "{hsts}" always;')

    return "\n".join(lines)


def build_method_guard(cfg: dict, indent: str = "    ") -> str:
    methods = get(cfg, "nginx", "allowed_methods", ["GET", "HEAD", "POST"])
    pattern = "|".join(methods)
    return (
        f"{indent}# Всё, что не в списке разрешённых методов, отбрасывается\n"
        f"{indent}# здесь и не доходит до Python.\n"
        f"{indent}if ($request_method !~ ^({pattern})$) {{\n"
        f"{indent}    return 405;\n"
        f"{indent}}}"
    )


def build_ssl_directives(cfg: dict, indent: str = "    ") -> str:
    tls = cfg["tls"]
    return "\n".join(
        f"{indent}{line}"
        for line in (
            f"ssl_certificate     {tls['cert_file']};",
            f"ssl_certificate_key {tls['key_file']};",
            "",
            "# Только современные протоколы. TLS 1.0/1.1 отключены.",
            "ssl_protocols             TLSv1.2 TLSv1.3;",
            "ssl_prefer_server_ciphers off;",
            "ssl_ciphers               ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;",
            "ssl_session_cache         shared:SSL:2m;",
            "ssl_session_timeout       1h;",
            "ssl_session_tickets       off;",
        )
    )


def build_servers(cfg: dict) -> str:
    """Собирает server-блоки: catch-all + рабочий, с TLS или без."""
    net = cfg["network"]
    tls = cfg["tls"]
    tls_on = bool(tls.get("enabled"))
    ip = net["server_ip"]
    names = " ".join([ip, *net.get("extra_allowed_hosts", [])])

    blocks: list[str] = []

    # --- Проверка живости самого nginx -------------------------------------
    # Отдельный сервер на loopback внутри контейнера. Порт 8081 не слушается
    # ни на одном внешнем интерфейсе и не публикуется наружу.
    # Причина отдельного блока: healthcheck ходит на 127.0.0.1, такой Host
    # не совпадает с server_name рабочего сервера и попал бы в catch-all,
    # получив 444 и вечно красный статус контейнера.
    blocks.append(
        "server {\n"
        "    listen      127.0.0.1:8081;\n"
        "    server_name _;\n"
        "    access_log  off;\n"
        "\n"
        "    location = /nginx-health {\n"
        "        default_type text/plain;\n"
        '        return 200 "ok\\n";\n'
        "    }\n"
        "\n"
        "    location / {\n"
        "        return 444;\n"
        "    }\n"
        "}"
    )

    # --- Catch-all: запрос с чужим Host обрывается без ответа. -------------
    # 444 закрывает соединение молча: сканеру не достаётся даже кода ошибки.
    blocks.append(
        "# Запрос с неизвестным Host закрывается без ответа (444).\n"
        "# Это отсекает сканеры, которые ходят по IP-диапазонам вслепую.\n"
        "server {\n"
        "    listen      8080 default_server;\n"
        "    server_name _;\n"
        "    return      444;\n"
        "}"
    )

    if tls_on:
        blocks.append(
            "server {\n"
            "    listen      8443 ssl default_server;\n"
            "    http2       on;\n"
            "    server_name _;\n"
            f"{build_ssl_directives(cfg)}\n"
            "    return      444;\n"
            "}"
        )

    # --- HTTP ---------------------------------------------------------------
    if tls_on and tls.get("redirect_http", True):
        blocks.append(
            "# Весь незашифрованный трафик уводится на HTTPS.\n"
            "server {\n"
            "    listen      8080;\n"
            f"    server_name {names};\n"
            "    return      301 https://$host$request_uri;\n"
            "}"
        )
        main_listen = "    listen      8443 ssl;\n    http2       on;\n" + build_ssl_directives(cfg) + "\n"
    else:
        main_listen = "    listen      8080;\n"

    blocks.append(
        "server {\n"
        f"{main_listen}"
        f"    server_name {names};\n"
        "\n"
        "{{ main_server_body }}\n"
        "}"
    )
    return "\n\n".join(blocks)


def render_template(text: str, values: dict[str, str]) -> str:
    """Подстановка {{ key }}. Повторяется, пока остаются известные ключи."""
    pattern = re.compile(r"\{\{\s*([a-z0-9_]+)\s*\}\}")

    for _ in range(10):
        def repl(match: re.Match) -> str:
            key = match.group(1)
            if key not in values:
                raise ConfigError(f"в шаблоне nginx неизвестный placeholder {{{{ {key} }}}}")
            return str(values[key])

        new_text = pattern.sub(repl, text)
        if new_text == text:
            return new_text
        text = new_text

    raise ConfigError("циклическая подстановка в шаблоне nginx")


def build_nginx_values(cfg: dict) -> dict[str, str]:
    ng = cfg["nginx"]
    net = cfg["network"]
    log_health = "" if ng.get("log_healthcheck") else "access_log off;"

    return {
        "worker_processes": ng["worker_processes"],
        "worker_connections": ng["worker_connections"],
        "worker_rlimit_nofile": ng.get("worker_rlimit_nofile", ng["worker_connections"] * 4),
        "keepalive_requests": ng.get("keepalive_requests", 1000),
        "keepalive_timeout": ng["keepalive_timeout"],
        "client_max_body_size": ng["client_max_body_size"],
        "client_body_timeout": ng["client_body_timeout"],
        "client_header_timeout": ng["client_header_timeout"],
        "send_timeout": ng["send_timeout"],
        "limit_zone_size": ng["limit_zone_size"],
        "rate_limit_general": ng["rate_limit_general"],
        "rate_limit_general_burst": ng["rate_limit_general_burst"],
        "rate_limit_auth": ng["rate_limit_auth"],
        "rate_limit_auth_burst": ng["rate_limit_auth_burst"],
        "rate_limit_admin": ng["rate_limit_admin"],
        "rate_limit_admin_burst": ng["rate_limit_admin_burst"],
        "conn_limit_per_ip": ng["conn_limit_per_ip"],
        "static_cache_max_age": ng["static_cache_max_age"],
        # Логи идут в stdout/stderr: контейнер работает с read-only
        # файловой системой, и логи забирает docker, а не файл на диске.
        "access_log_state": "/dev/stdout main" if ng.get("access_log_enabled", True) else "off",
        "healthcheck_access_log": log_health,
        "server_ip": net["server_ip"],
        "method_guard": build_method_guard(cfg, indent="    "),
        "main_server_body": SERVER_BODY.read_text(encoding="utf-8").rstrip("\n"),
        "servers": build_servers(cfg),
        "server_tokens": "off" if cfg.get("security", {}).get("hide_server_version", True) else "on",
    }


# --------------------------------------------------------------------------
# .env для docker compose
# --------------------------------------------------------------------------

def build_pg_hba(cfg: dict) -> str:
    """Правила доступа к PostgreSQL.

    Порядок строк важен: PostgreSQL применяет первое подходящее правило.
    """
    db = cfg["database"]
    subnet = cfg["network"]["data_subnet"]
    host_type = "hostssl" if db.get("tls_enabled", False) else "host"

    return f"""# СГЕНЕРИРОВАНО scripts/render_config.py — НЕ РЕДАКТИРОВАТЬ.
# Правьте config/selectashop.toml и выполняйте: make config
#
# TYPE  DATABASE  USER  ADDRESS  METHOD

# Локальный сокет внутри контейнера. Нужен служебным скриптам образа при
# первичной инициализации и проверке живости (pg_isready). Доверие здесь
# ничего не ослабляет: единственный процесс в контейнере — сам PostgreSQL,
# и тот, кто получил в нём выполнение кода, уже работает от его имени.
local   all       all                           trust

# Единственный сетевой доступ — из внутренней сети data, где находятся
# только приложение и воркер рассылки. {"Обязательно по TLS." if host_type == "hostssl" else "БЕЗ шифрования канала."}
{host_type:<8}all       all   {subnet:<18}scram-sha-256

# Всё остальное отвергается явно. Строка избыточна — по умолчанию
# PostgreSQL и так отказывает, — но делает намерение видимым.
host    all       all   0.0.0.0/0             reject
host    all       all   ::/0                  reject
"""


def build_env(cfg: dict) -> str:
    project = cfg["project"]
    net = cfg["network"]
    lim = cfg["limits"]
    registry = project.get("image_registry", "")

    pairs = {
        "COMPOSE_PROJECT_NAME": project["name"],
        "NGINX_IMAGE": registry + project["nginx_image"],
        "PYTHON_IMAGE": registry + project["python_image"],
        "BIND_ADDRESS": net["bind_address"],
        "HTTP_PORT": net["http_port"],
        "HTTPS_PORT": net["https_port"],
        "EDGE_SUBNET": net["edge_subnet"],
        "INTERNAL_SUBNET": net["internal_subnet"],
        "WEB_MEMORY": lim["web_memory"],
        "WEB_CPUS": lim["web_cpus"],
        "WEB_PIDS": lim["web_pids"],
        "NGINX_MEMORY": lim["nginx_memory"],
        "NGINX_CPUS": lim["nginx_cpus"],
        "NGINX_PIDS": lim["nginx_pids"],
        "TMPFS_SIZE": lim["tmpfs_size"],
        "TLS_ENABLED": str(cfg["tls"].get("enabled", False)).lower(),
    }

    db = cfg.get("database", {})
    if db.get("engine") == "postgresql":
        tuning = db.get("tuning", {})
        pairs.update({
            "POSTGRES_IMAGE": registry + project.get("postgres_image", "postgres:16-bookworm"),
            "DATA_SUBNET": net["data_subnet"],
            "DB_NAME": db["name"],
            "DB_SUPERUSER": db["superuser"],
            "DB_SUPERUSER_PASSWORD": db["superuser_password"],
            "DB_OWNER_USER": db["owner_user"],
            "DB_OWNER_PASSWORD": db["owner_password"],
            "DB_APP_USER": db["app_user"],
            "DB_APP_PASSWORD": db["app_password"],
            "DB_BACKUP_USER": db["backup_user"],
            "DB_BACKUP_PASSWORD": db["backup_password"],
            "PG_SSL": "on" if db.get("tls_enabled") else "off",
            "PG_SHARED_BUFFERS": tuning.get("shared_buffers", "128MB"),
            "PG_EFFECTIVE_CACHE_SIZE": tuning.get("effective_cache_size", "256MB"),
            "PG_WORK_MEM": tuning.get("work_mem", "4MB"),
            "PG_MAINTENANCE_WORK_MEM": tuning.get("maintenance_work_mem", "64MB"),
            "PG_WAL_BUFFERS": tuning.get("wal_buffers", "4MB"),
            "PG_MAX_CONNECTIONS": tuning.get("max_connections", 20),
            "PG_CHECKPOINT_COMPLETION_TARGET": tuning.get("checkpoint_completion_target", 0.9),
            "PG_RANDOM_PAGE_COST": tuning.get("random_page_cost", 1.1),
            "PG_LOG_MIN_DURATION": tuning.get("log_min_duration_statement", 500),
            "DB_MEMORY": lim.get("db_memory", "320m"),
            "DB_CPUS": lim.get("db_cpus", "0.60"),
            "DB_PIDS": lim.get("db_pids", 128),
        })
    header = (
        "# СГЕНЕРИРОВАНО scripts/render_config.py — НЕ РЕДАКТИРОВАТЬ.\n"
        "# Правьте config/selectashop.toml и выполняйте: make config\n"
    )
    return header + "\n".join(f"{k}={v}" for k, v in pairs.items()) + "\n"


TLS_OVERRIDE = """# СГЕНЕРИРОВАНО scripts/render_config.py — НЕ РЕДАКТИРОВАТЬ.
# Подключается только при [tls].enabled = true.
services:
  nginx:
    ports:
      - "${BIND_ADDRESS}:${HTTPS_PORT}:8443"
    volumes:
      - ./deploy/generated/certs:/etc/nginx/certs:ro
"""


EGRESS_OVERRIDE = """# СГЕНЕРИРОВАНО scripts/render_config.py — НЕ РЕДАКТИРОВАТЬ.
# Подключается только при [network].web_egress = true.
# Даёт контейнеру web доступ в интернет (нужен для платёжных API и SMTP).
services:
  web:
    networks:
      internal: {}
      egress: {}

networks:
  egress:
    driver: bridge
"""


def write(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def main() -> int:
    try:
        cfg = load()
        warnings = validate(cfg)
    except ConfigError as exc:
        print(f"\n  КОНФИГУРАЦИЯ ОТКЛОНЕНА\n\n  {exc}\n", file=sys.stderr)
        return 2

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Заголовки безопасности выносятся в отдельный файл и включаются
    # через include в КАЖДЫЙ location, где есть свой add_header.
    # Причина: в nginx add_header внутри location полностью отменяет
    # заголовки, унаследованные от server. Без этого повторного include
    # статика отдавалась бы вообще без CSP и X-Frame-Options.
    write(
        OUT_DIR / "snippets" / "security_headers.conf",
        "# СГЕНЕРИРОВАНО scripts/render_config.py — НЕ РЕДАКТИРОВАТЬ.\n"
        + build_security_headers(cfg, indent="")
        + "\n",
    )

    write(
        OUT_DIR / "snippets" / "proxy_hide_security_headers.conf",
        "# СГЕНЕРИРОВАНО scripts/render_config.py — НЕ РЕДАКТИРОВАТЬ.\n"
        + build_proxy_hide_headers(cfg).replace("        ", "")
        + "\n",
    )

    if cfg.get("database", {}).get("engine") == "postgresql":
        write(OUT_DIR / "pg_hba.conf", build_pg_hba(cfg))

    template = TEMPLATE.read_text(encoding="utf-8")
    nginx_conf = render_template(template, build_nginx_values(cfg))
    write(OUT_DIR / "nginx.conf", nginx_conf)

    # .env содержит только несекретные параметры, но режим всё равно сужаем.
    write(OUT_DIR / ".env", build_env(cfg), mode=0o600)

    tls_path = OUT_DIR / "docker-compose.tls.yml"
    if cfg["tls"].get("enabled"):
        write(tls_path, TLS_OVERRIDE)
        (OUT_DIR / "certs").mkdir(parents=True, exist_ok=True)
    elif tls_path.exists():
        tls_path.unlink()

    egress_path = OUT_DIR / "docker-compose.egress.yml"
    if cfg["network"].get("web_egress"):
        write(egress_path, EGRESS_OVERRIDE)
    elif egress_path.exists():
        egress_path.unlink()

    print("  сгенерировано:")
    for name in (
        "nginx.conf",
        "snippets/security_headers.conf",
        "snippets/proxy_hide_security_headers.conf",
        ".env",
    ):
        print(f"    deploy/generated/{name}")
    if (OUT_DIR / "pg_hba.conf").exists():
        print("    deploy/generated/pg_hba.conf")
    if tls_path.exists():
        print("    deploy/generated/docker-compose.tls.yml")
    if egress_path.exists():
        print("    deploy/generated/docker-compose.egress.yml")

    if warnings:
        print("\n  ПРЕДУПРЕЖДЕНИЯ:")
        for item in warnings:
            print(f"    !  {item}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

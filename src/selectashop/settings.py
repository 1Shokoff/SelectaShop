"""Настройки Django для SelectaShop.

Все значения берутся из единственного файла конфигурации проекта
(config/selectashop.toml), который внутри контейнера смонтирован
только для чтения в /etc/selectashop/selectashop.toml.

В этом модуле НЕТ захардкоженных секретов и НЕТ чтения россыпи
переменных окружения: один источник правды, одно место для аудита.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

MIN_SECRET_KEY_LEN = 50


# =============================================================================
#  Загрузка конфигурации
# =============================================================================

def _config_path() -> Path:
    """Путь к конфигу: переменная окружения, затем контейнерный, затем локальный."""
    import os

    override = os.environ.get("SELECTASHOP_CONFIG")
    if override:
        return Path(override)

    container = Path("/etc/selectashop/selectashop.toml")
    if container.exists():
        return container

    return BASE_DIR.parent / "config" / "selectashop.toml"


def _load_config() -> dict:
    path = _config_path()
    if not path.exists():
        raise ImproperlyConfigured(
            f"не найден файл конфигурации {path}. "
            "Создайте его командой `make init-config`."
        )
    with path.open("rb") as fh:
        return tomllib.load(fh)


CONFIG = _load_config()

_django = CONFIG.get("django", {})
_net = CONFIG.get("network", {})
_tls = CONFIG.get("tls", {})
_sec = CONFIG.get("security", {})
_db = CONFIG.get("database", {})


# =============================================================================
#  Ключ подписи
# =============================================================================
#  Отказ при пустом или коротком ключе сделан намеренно. Дефолтное значение
#  здесь было бы худшим из возможных решений: проект тихо уехал бы в
#  продакшен с общеизвестным ключом, а это подделка сессий и подписанных
#  токенов сброса пароля.

SECRET_KEY = _django.get("secret_key", "")

if not SECRET_KEY or len(SECRET_KEY) < MIN_SECRET_KEY_LEN:
    raise ImproperlyConfigured(
        f"[django].secret_key пуст или короче {MIN_SECRET_KEY_LEN} символов. "
        "Сгенерируйте: make secret"
    )
if SECRET_KEY.startswith("django-insecure"):
    raise ImproperlyConfigured(
        "[django].secret_key содержит префикс django-insecure — это ключ "
        "из шаблона, он не является секретом."
    )


# =============================================================================
#  Режим отладки и разрешённые хосты
# =============================================================================

DEBUG = bool(_django.get("debug", False))

SERVER_IP = _net.get("server_ip", "")
if not SERVER_IP:
    raise ImproperlyConfigured("[network].server_ip не задан")

# 127.0.0.1 и localhost нужны для healthcheck контейнера, который ходит
# на loopback изнутри. Снаружи эти значения Host недостижимы: их раньше
# отбрасывает catch-all сервер nginx, возвращая 444.
ALLOWED_HOSTS = [
    SERVER_IP,
    *_net.get("extra_allowed_hosts", []),
    "127.0.0.1",
    "localhost",
]

# Заголовок Host из X-Forwarded-Host не используется: клиент может прислать
# его сам, а Django строит по нему абсолютные ссылки, в том числе в письмах
# сброса пароля. Это классический вектор host header injection.
USE_X_FORWARDED_HOST = False
USE_X_FORWARDED_PORT = False


# =============================================================================
#  Транспортная безопасность
# =============================================================================

TLS_ENABLED = bool(_tls.get("enabled", False))


def _origin(scheme: str, port: int, default_port: int) -> str:
    host = SERVER_IP if port == default_port else f"{SERVER_IP}:{port}"
    return f"{scheme}://{host}"


_configured_origins = list(_sec.get("csrf_trusted_origins", []))
if _configured_origins:
    CSRF_TRUSTED_ORIGINS = _configured_origins
elif TLS_ENABLED:
    CSRF_TRUSTED_ORIGINS = [_origin("https", int(_net.get("https_port", 443)), 443)]
else:
    CSRF_TRUSTED_ORIGINS = [_origin("http", int(_net.get("http_port", 80)), 80)]

# Основной редирект на HTTPS делает nginx — запрос до Django доходит уже
# по нужной схеме, и эта настройка в штатном режиме не срабатывает ни разу.
# Она включена как страховка на случай, если приложение когда-нибудь
# окажется доступно в обход nginx: тогда оно откажется отвечать по HTTP
# само, а не будет молча раздавать сессии открытым текстом.
SECURE_SSL_REDIRECT = TLS_ENABLED

# Исключение для проверки живости: healthcheck контейнера ходит на
# 127.0.0.1:8000 по HTTP и получил бы 301 вместо 200, из-за чего контейнер
# навсегда остался бы в статусе unhealthy.
SECURE_REDIRECT_EXEMPT = [r"^healthz$"]

# Django узнаёт о том, что исходный запрос был по HTTPS, только из этого
# заголовка. Доверять ему можно ровно потому, что попасть в контейнер
# в обход nginx невозможно: порт 8000 не опубликован, а сеть помечена
# internal. Если это когда-нибудь изменится — строку надо пересмотреть.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https") if TLS_ENABLED else None

_hsts = int(_tls.get("hsts_seconds", 0)) if TLS_ENABLED else 0
SECURE_HSTS_SECONDS = _hsts
SECURE_HSTS_INCLUDE_SUBDOMAINS = bool(_tls.get("hsts_include_subdomains", False)) and _hsts > 0
SECURE_HSTS_PRELOAD = bool(_tls.get("hsts_preload", False)) and _hsts > 0

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = _sec.get("referrer_policy", "same-origin")
SECURE_CROSS_ORIGIN_OPENER_POLICY = _sec.get("cross_origin_opener_policy", "same-origin")
X_FRAME_OPTIONS = _sec.get("x_frame_options", "DENY")


# =============================================================================
#  Cookie
# =============================================================================
#  Флаг Secure привязан к наличию TLS. Выставить его без TLS нельзя —
#  браузер просто не сохранит cookie и сайт перестанет работать.
#  Именно поэтому включение админки при выключенном TLS заблокировано
#  в scripts/render_config.py: иначе пароль ушёл бы открытым текстом.

SESSION_COOKIE_SECURE = TLS_ENABLED
CSRF_COOKIE_SECURE = TLS_ENABLED

SESSION_COOKIE_HTTPONLY = True
# Токен CSRF читается из скрытого поля формы ({% csrf_token %}), доступ
# к нему из JavaScript не нужен, поэтому cookie тоже закрыта от скриптов.
CSRF_COOKIE_HTTPONLY = True

SESSION_COOKIE_SAMESITE = _sec.get("session_cookie_samesite", "Lax")
CSRF_COOKIE_SAMESITE = _sec.get("csrf_cookie_samesite", "Lax")

SESSION_COOKIE_NAME = "selectashop_session"
CSRF_COOKIE_NAME = "selectashop_csrf"

SESSION_COOKIE_AGE = int(_sec.get("session_cookie_age", 1209600))
SESSION_EXPIRE_AT_BROWSER_CLOSE = bool(_sec.get("session_expire_at_browser_close", False))


# =============================================================================
#  База данных
# =============================================================================
#  engine = "none" — этап 0: контейнера БД ещё нет, приложение работает
#  без единого подключения. Это минимально возможная поверхность атаки
#  для сайта-заглушки.

DB_ENGINE = _db.get("engine", "none")
DB_TLS = bool(_db.get("tls_enabled", False))


def _postgres(user_key: str, password_key: str) -> dict:
    """Параметры подключения для одной из ролей БД."""
    options: dict = {}
    if DB_TLS:
        # verify-full проверяет и цепочку сертификата, и совпадение имени
        # хоста. Более слабые режимы (require, prefer) шифруют канал, но
        # не защищают от подмены сервера, то есть не дают главного.
        options["sslmode"] = _db.get("ssl_mode", "verify-full")
        root_cert = _db.get("ssl_root_cert", "")
        if root_cert:
            options["sslrootcert"] = root_cert
    else:
        options["sslmode"] = "disable"

    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _db.get("name", "selectashop"),
        "USER": _db.get(user_key, ""),
        "PASSWORD": _db.get(password_key, ""),
        "HOST": _db.get("host", "db"),
        "PORT": int(_db.get("port", 5432)),
        "CONN_MAX_AGE": int(_db.get("conn_max_age", 60)),
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": options,
    }


if DB_ENGINE == "none":
    DATABASES = {}
elif DB_ENGINE == "sqlite":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": Path("/var/lib/selectashop") / f"{_db.get('name', 'selectashop')}.sqlite3",
        }
    }
elif DB_ENGINE == "postgresql":
    # Две роли, два подключения.
    #
    #   default — роль приложения. Имеет только SELECT/INSERT/UPDATE/DELETE.
    #             Через неё идут все запросы в обычной работе.
    #   admin   — владелец схемы, права DDL. Используется ИСКЛЮЧИТЕЛЬНО
    #             миграциями: `manage.py migrate --database=admin`.
    #
    # Смысл разделения прямой: успешная SQL-инъекция в приложении не сможет
    # выполнить DROP TABLE, CREATE FUNCTION или прочитать pg_authid —
    # у роли приложения таких прав просто нет.
    DATABASES = {
        "default": _postgres("app_user", "app_password"),
        "admin": _postgres("owner_user", "owner_password"),
    }
else:
    raise ImproperlyConfigured(
        f"[database].engine = {DB_ENGINE!r}; ожидается none|sqlite|postgresql"
    )

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# =============================================================================
#  Приложения и middleware
# =============================================================================
#  Состав зависит от наличия БД. Пока БД нет, подсистемы аутентификации,
#  сессий и сообщений не подключаются вовсе: неработающий код лучше
#  не загружать, чем загрузить и надеяться, что его не вызовут.

ADMIN_ENABLED = bool(_django.get("admin_enabled", False))
DB_AVAILABLE = DB_ENGINE != "none"

if ADMIN_ENABLED and not DB_AVAILABLE:
    raise ImproperlyConfigured(
        "[django].admin_enabled = true, но [database].engine = none. "
        "Админке необходима база данных."
    )
if ADMIN_ENABLED and not TLS_ENABLED:
    raise ImproperlyConfigured(
        "[django].admin_enabled = true при выключенном TLS: пароль "
        "администратора передавался бы открытым текстом. "
        "Включите [tls].enabled."
    )

# Путь админки. Смена пути не является защитой сама по себе, но убирает
# из логов весь шумовой перебор ботов по /admin/, на фоне которого
# невозможно заметить целенаправленную атаку.
ADMIN_URL = str(_django.get("admin_url", "")).lstrip("/")

INSTALLED_APPS = [
    "django.contrib.staticfiles",
    "core.apps.CoreConfig",
]

# CsrfViewMiddleware присутствует всегда, в том числе пока нет базы данных:
# защита от CSRF работает на cookie с токеном и к БД не обращается
# (CSRF_USE_SESSIONS = False по умолчанию). Держать её включённой с самого
# начала дешевле, чем вспоминать о ней в момент появления первой формы.
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

if DB_AVAILABLE:
    INSTALLED_APPS = [
        "django.contrib.contenttypes",
        "django.contrib.auth",
        "django.contrib.sessions",
        "django.contrib.messages",
        *INSTALLED_APPS,
        "accounts.apps.AccountsConfig",
        "notifications.apps.NotificationsConfig",
    ]

    # Собственная модель пользователя. Менять AUTH_USER_MODEL после
    # появления данных практически невозможно — поэтому она заведена
    # сразу, до первой миграции.
    AUTH_USER_MODEL = "accounts.User"

    # Один бэкенд вместо стандартного ModelBackend: вход по логину ИЛИ
    # по адресу почты, с выравниванием времени ответа.
    AUTHENTICATION_BACKENDS = ["accounts.backends.EmailOrUsernameBackend"]
    MIDDLEWARE = [
        "django.middleware.security.SecurityMiddleware",
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
        "django.middleware.clickjacking.XFrameOptionsMiddleware",
    ]

if ADMIN_ENABLED:
    INSTALLED_APPS.insert(0, "django.contrib.admin")

ROOT_URLCONF = "selectashop.urls"
WSGI_APPLICATION = "selectashop.wsgi.application"

_context_processors = [
    "django.template.context_processors.request",
]
if DB_AVAILABLE:
    _context_processors += [
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": _context_processors},
    }
]


# =============================================================================
#  Пароли
# =============================================================================
#  Argon2id — победитель Password Hashing Competition и рекомендация OWASP.
#  Django по умолчанию использует PBKDF2, который на порядок дешевле
#  перебирать на GPU. Порядок в списке важен: первый хешер используется
#  для новых паролей, остальные — для проверки старых.

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 10},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


# =============================================================================
#  Локализация
# =============================================================================

LANGUAGE_CODE = _django.get("language_code", "ru-ru")
TIME_ZONE = _django.get("time_zone", "UTC")
USE_I18N = True
USE_TZ = True


# =============================================================================
#  Статика и медиа
# =============================================================================
#  Раздаёт их nginx напрямую; Django только собирает статику в общий том.
#  ManifestStaticFilesStorage добавляет к именам файлов хеш содержимого —
#  без этого заголовок Cache-Control: immutable на 30 суток означал бы,
#  что обновлённый CSS не доедет до вернувшихся посетителей.

STATIC_URL = "/static/"
STATIC_ROOT = Path("/var/www/static")
STATICFILES_DIRS = [BASE_DIR / "static"] if (BASE_DIR / "static").is_dir() else []

MEDIA_URL = "/media/"
MEDIA_ROOT = Path("/var/www/media")

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"
    },
}

# Загружаемые файлы не должны быть исполняемыми и не должны быть доступны
# на запись кому-либо, кроме владельца процесса.
FILE_UPLOAD_PERMISSIONS = 0o644
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o755


# =============================================================================
#  Лимиты на входящий запрос
# =============================================================================
#  Второй рубеж после nginx. Защищает от DoS через гигантские формы:
#  разбор 100000 полей съедает CPU задолго до попадания в бизнес-логику.

DATA_UPLOAD_MAX_MEMORY_SIZE = int(_django.get("data_upload_max_memory_size", 2621440))
DATA_UPLOAD_MAX_NUMBER_FIELDS = int(_django.get("data_upload_max_number_fields", 1000))
FILE_UPLOAD_MAX_MEMORY_SIZE = int(_django.get("file_upload_max_memory_size", 2621440))


# =============================================================================
#  Логирование
# =============================================================================
#  Только stdout/stderr: логи забирает docker. Файлов на диске нет —
#  на VPS с 1 GB переполнение диска логами это реальный сценарий отказа.

LOG_LEVEL = str(_django.get("log_level", "INFO")).upper()

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "{asctime} {levelname} {name} {message}",
            "style": "{",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "stream": sys.stdout,
            "formatter": "standard",
        }
    },
    "root": {"handlers": ["console"], "level": LOG_LEVEL},
    "loggers": {
        "django": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
        # Отдельный логгер: сюда Django пишет отклонённые Host, сломанные
        # CSRF-токены и прочие сигналы, по которым видно сканирование.
        "django.security": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}


# =============================================================================
#  Криптографические ключи
# =============================================================================
#  Разбираются на старте, чтобы ошибка в конфигурации обнаружилась при
#  запуске контейнера, а не при первой попытке регистрации.

from selectashop import crypto as _crypto  # noqa: E402

if DB_AVAILABLE:
    try:
        DATA_ENCRYPTION_KEY = _crypto.decode_key(
            _sec.get("data_encryption_key", ""), name="data_encryption_key"
        )
        BLIND_INDEX_PEPPER = _crypto.decode_key(
            _sec.get("blind_index_pepper", ""), name="blind_index_pepper"
        )
        TOKEN_PEPPER = _crypto.decode_key(
            _sec.get("token_pepper", ""), name="token_pepper"
        )
    except ValueError as exc:
        raise ImproperlyConfigured(
            f"{exc}\nСгенерируйте ключи заново: make init-config"
        ) from exc

    if len({DATA_ENCRYPTION_KEY, BLIND_INDEX_PEPPER, TOKEN_PEPPER}) != 3:
        raise ImproperlyConfigured(
            "Ключи в [security] совпадают между собой. Они должны быть "
            "разными: компрометация одного не должна раскрывать остальные."
        )

    ENCRYPTION_KEY_VERSION = int(_sec.get("encryption_key_version", 1))
else:
    DATA_ENCRYPTION_KEY = BLIND_INDEX_PEPPER = TOKEN_PEPPER = b""
    ENCRYPTION_KEY_VERSION = 1


# =============================================================================
#  Учётные записи
# =============================================================================

_accounts = CONFIG.get("accounts", {})

ACCOUNTS = {
    "unverified_email_ttl_hours": int(_accounts.get("unverified_email_ttl_hours", 24)),
    "email_verify_token_ttl_hours": int(_accounts.get("email_verify_token_ttl_hours", 24)),
    "password_reset_token_ttl_hours": int(_accounts.get("password_reset_token_ttl_hours", 2)),
    "username_min_length": int(_accounts.get("username_min_length", 4)),
    "username_max_length": int(_accounts.get("username_max_length", 32)),
    "reserved_usernames": tuple(_accounts.get("reserved_usernames", ())),
    "blocked_email_domains": tuple(_accounts.get("blocked_email_domains", ())),
    "password_min_length": int(_accounts.get("password_min_length", 10)),
    "max_emails_per_address_per_hour": int(_accounts.get("max_emails_per_address_per_hour", 3)),
    "max_registrations_per_ip_per_hour": int(_accounts.get("max_registrations_per_ip_per_hour", 5)),
    "max_login_failures": int(_accounts.get("max_login_failures", 10)),
    "login_lockout_minutes": int(_accounts.get("login_lockout_minutes", 15)),
    "security_event_retention_days": int(_accounts.get("security_event_retention_days", 90)),
}

# Минимальная длина пароля берётся из того же конфига, чтобы значение
# не задваивалось между валидатором Django и формой регистрации.
for _validator in AUTH_PASSWORD_VALIDATORS:
    if _validator["NAME"].endswith("MinimumLengthValidator"):
        _validator["OPTIONS"] = {"min_length": ACCOUNTS["password_min_length"]}


# =============================================================================
#  Юридические документы
# =============================================================================
#  Тексты лежат файлами и версионируются git. В базе хранится ключ,
#  версия и SHA-256 текста на момент согласия.

_legal = CONFIG.get("legal", {})

# В репозитории документы лежат рядом с src/, в образе — внутри /app.
# Проверяем оба расположения, чтобы один и тот же код работал и при
# локальном запуске, и в контейнере.
_legal_dir_name = _legal.get("documents_dir", "legal")
LEGAL_DOCUMENTS_DIR = next(
    (
        candidate
        for candidate in (BASE_DIR / _legal_dir_name, BASE_DIR.parent / _legal_dir_name)
        if candidate.is_dir()
    ),
    BASE_DIR.parent / _legal_dir_name,
)

LEGAL_DOCUMENTS = {
    "pdn_consent": {
        "version": str(_legal.get("pdn_consent_version", "1.0")),
        "filename": "pdn_consent.md",
        "title": "Согласие на обработку персональных данных",
    },
    "terms_of_service": {
        "version": str(_legal.get("terms_version", "1.0")),
        "filename": "terms_of_service.md",
        "title": "Пользовательское соглашение",
    },
}

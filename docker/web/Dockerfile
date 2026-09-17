# Директива `# syntax=` намеренно не используется: она заставляет BuildKit
# скачивать отдельный образ фронтенда с Docker Hub при каждой сборке.
# На сервере в РФ, где Docker Hub недоступен, это ломает сборку целиком,
# а никаких возможностей за пределами базового синтаксиса здесь не нужно.
# =============================================================================
#  Образ приложения SelectaShop
# =============================================================================
#  Двухстадийная сборка: компиляторы и заголовочные файлы нужны только для
#  установки зависимостей и в финальный образ не попадают. Это и меньше
#  размер, и меньше того, чем можно воспользоваться после проникновения.
# =============================================================================

ARG PYTHON_IMAGE=python:3.12-slim-bookworm

# -----------------------------------------------------------------------------
#  Стадия 1: сборка зависимостей
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# build-essential и libffi-dev нужны для сборки argon2-cffi,
# если для платформы не найдётся готового wheel.
RUN apt-get update \
 && apt-get install --no-install-recommends -y \
        build-essential \
        libffi-dev \
 && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt


# -----------------------------------------------------------------------------
#  Стадия 2: рантайм
# -----------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

# Фиксированные uid/gid. Важно для прав на общие тома: nginx читает
# статику, собранную этим пользователем, а при плавающем uid права
# после пересборки образа разъезжаются.
ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DJANGO_SETTINGS_MODULE=selectashop.settings \
    SELECTASHOP_CONFIG=/etc/selectashop/selectashop.toml \
    PATH="/opt/venv/bin:${PATH}"

# Обновление системных пакетов закрывает CVE базового образа.
# Никаких дополнительных утилит: нет curl, нет компилятора, нет shell-инструментов,
# которыми удобно пользоваться после проникновения.
RUN apt-get update \
 && apt-get upgrade -y \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

RUN groupadd --gid ${APP_GID} app \
 && useradd --uid ${APP_UID} --gid ${APP_GID} --no-create-home --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=root:root src/ /app/
COPY --chown=root:root docker/web/gunicorn.conf.py /etc/gunicorn/gunicorn.conf.py
COPY --chown=root:root docker/web/entrypoint.sh /usr/local/bin/entrypoint.sh

# Код принадлежит root и доступен приложению только на чтение и исполнение.
# Процесс, работающий от app, не может переписать собственные исходники —
# это отрезает самый простой способ закрепиться после RCE.
RUN chmod -R a-w /app /opt/venv /etc/gunicorn \
 && chmod 0755 /usr/local/bin/entrypoint.sh

# Каталоги общих томов создаются здесь и с нужным владельцем: docker
# переносит права из образа в новый named volume при первом монтировании.
RUN mkdir -p /var/www/static /var/www/media \
 && chown ${APP_UID}:${APP_GID} /var/www/static /var/www/media \
 && chmod 0755 /var/www/static /var/www/media

USER ${APP_UID}:${APP_GID}

EXPOSE 8000

# Проверка живости обращается к локальному порту и не трогает базу.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

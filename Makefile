# =============================================================================
#  SelectaShop
# =============================================================================
#  Обычный порядок первого запуска:
#
#      make init-config          создать config/selectashop.toml
#      $EDITOR config/selectashop.toml    вписать [network].server_ip
#      make config               сгенерировать конфиги nginx и compose
#      make build && make up
#
#  После ЛЮБОЙ правки config/selectashop.toml:  make config && make restart
# =============================================================================

.DEFAULT_GOAL := help
SHELL := /bin/sh

ENV_FILE   := deploy/generated/.env
BASE_FILE  := docker-compose.yml
TLS_FILE   := deploy/generated/docker-compose.tls.yml
EGR_FILE   := deploy/generated/docker-compose.egress.yml

# Оверлеи подключаются, только если их сгенерировал render_config.py.
COMPOSE_FILES := -f $(BASE_FILE)
ifneq ($(wildcard $(TLS_FILE)),)
COMPOSE_FILES += -f $(TLS_FILE)
endif
ifneq ($(wildcard $(EGR_FILE)),)
COMPOSE_FILES += -f $(EGR_FILE)
endif

COMPOSE := docker compose --env-file $(ENV_FILE) $(COMPOSE_FILES)

.PHONY: help init-config secret config build up down restart logs ps \
        tls-selfsigned db-cert audit audit-django audit-python audit-deps \
        audit-nginx migrate create-owner grant-role delete-account purge psql mail \
        shell check clean

help:
	@echo ''
	@echo '  SelectaShop — доступные команды'
	@echo ''
	@echo '  Настройка'
	@echo '    make init-config      создать config/selectashop.toml из шаблона'
	@echo '    make secret           напечатать новый SECRET_KEY'
	@echo '    make config           сгенерировать конфиги из единого файла'
	@echo '    make tls-selfsigned   самоподписанный сертификат для работы по IP'
	@echo '    make db-cert          сертификат для канала приложение <-> БД'
	@echo ''
	@echo '  Запуск'
	@echo '    make build            собрать образ приложения'
	@echo '    make up               поднять сервисы'
	@echo '    make down             остановить сервисы'
	@echo '    make restart          перезапустить оба сервиса вместе'
	@echo '    make logs             смотреть логи'
	@echo '    make ps               состояние контейнеров'
	@echo ''
	@echo '  База данных'
	@echo '    make migrate          применить миграции (ролью-владельцем)'
	@echo '    make create-owner     создать владельца магазина'
	@echo '    make grant-role       сменить роль: ARGS="логин admin"'
	@echo '    make delete-account   удалить: ARGS="логин" или ARGS="логин --hard"'
	@echo '    make mail             журнал воркера рассылки (тут ссылки в режиме console)'
	@echo '    make purge            удалить просроченные регистрации и старые события'
	@echo '    make psql             консоль psql под ролью приложения'
	@echo ''
	@echo '  Безопасность'
	@echo '    make audit            все проверки разом'
	@echo '    make audit-django     django check --deploy'
	@echo '    make audit-python     статический анализ кода (bandit)'
	@echo '    make audit-deps       уязвимости в зависимостях (pip-audit)'
	@echo '    make audit-nginx      проверка конфига nginx (nginx -t, gixy)'
	@echo ''

# -----------------------------------------------------------------------------
#  Настройка
# -----------------------------------------------------------------------------

init-config:
	@python3 scripts/init_config.py

secret:
	@python3 -c "import secrets,string; a=string.ascii_letters+string.digits+'!#\$$%&()*+,-./:;<=>?@[]^_{|}~'; print(''.join(secrets.choice(a) for _ in range(64)))"

config:
	@python3 scripts/render_config.py

tls-selfsigned:
	@sh scripts/gen_selfsigned_cert.sh

db-cert:
	@sh scripts/gen_db_cert.sh

# -----------------------------------------------------------------------------
#  Запуск
# -----------------------------------------------------------------------------
#  Каждая цель зависит от $(ENV_FILE): забыть `make config` после правки
#  конфига невозможно по построению.

$(ENV_FILE):
	@python3 scripts/render_config.py

build: $(ENV_FILE)
	$(COMPOSE) build

up: $(ENV_FILE)
	$(COMPOSE) up -d
	@echo ''
	@$(COMPOSE) ps

down:
	$(COMPOSE) down

# Оба сервиса перезапускаются вместе: nginx кеширует IP апстрима с момента
# старта, и перезапуск одного лишь web оставил бы его стучать в пустоту.
restart: $(ENV_FILE)
	$(COMPOSE) up -d --force-recreate

logs:
	$(COMPOSE) logs -f --tail=100

ps:
	$(COMPOSE) ps

shell:
	$(COMPOSE) exec web /bin/sh

# -----------------------------------------------------------------------------
#  База данных
# -----------------------------------------------------------------------------
#  Миграции идут ролью-владельцем схемы: у роли приложения нет прав DDL,
#  и это намеренно.

migrate: $(ENV_FILE)
	$(COMPOSE) exec web python manage.py migrate --database=admin

create-owner: $(ENV_FILE)
	$(COMPOSE) exec web python manage.py create_owner $(ARGS)

grant-role: $(ENV_FILE)
	$(COMPOSE) exec web python manage.py grant_role $(ARGS)

# Обезличивание по умолчанию, полное удаление — с флагом --hard.
delete-account: $(ENV_FILE)
	$(COMPOSE) exec web python manage.py delete_account $(ARGS)

# В режиме [email].backend = "console" письма печатаются сюда целиком,
# вместе со ссылкой подтверждения.
mail:
	$(COMPOSE) logs -f --tail=200 worker

purge: $(ENV_FILE)
	$(COMPOSE) exec web python manage.py purge_expired

psql: $(ENV_FILE)
	@$(COMPOSE) exec db psql \
	    "host=/var/run/postgresql dbname=$$(grep '^DB_NAME=' $(ENV_FILE) | cut -d= -f2-) user=$$(grep '^DB_APP_USER=' $(ENV_FILE) | cut -d= -f2-)"

# -----------------------------------------------------------------------------
#  Аудит безопасности
# -----------------------------------------------------------------------------

audit: audit-django audit-python audit-deps audit-nginx
	@echo ''
	@echo '  Аудит завершён.'

audit-django: $(ENV_FILE)
	@echo ''
	@echo '=== Django: проверка настроек развёртывания ==============='
	@$(COMPOSE) run --rm --no-deps web python manage.py check --deploy

audit-python:
	@echo ''
	@echo '=== bandit: статический анализ кода ======================='
	@bandit -q -r src/ scripts/ -f screen || true

audit-deps:
	@echo ''
	@echo '=== pip-audit: уязвимости в зависимостях =================='
	@pip-audit -r requirements.txt --progress-spinner off || true

audit-nginx: $(ENV_FILE)
	@echo ''
	@echo '=== nginx: синтаксис конфигурации ========================='
	@docker run --rm \
	    -v "$(CURDIR)/deploy/generated/nginx.conf:/etc/nginx/nginx.conf:ro" \
	    -v "$(CURDIR)/deploy/generated/snippets:/etc/nginx/snippets:ro" \
	    $$(grep '^NGINX_IMAGE=' $(ENV_FILE) | cut -d= -f2-) nginx -t
	@echo ''
	@echo '=== gixy: анализ конфигурации на уязвимости ==============='
	@gixy deploy/generated/nginx.conf || true

check: audit

clean:
	$(COMPOSE) down -v
	rm -rf deploy/generated

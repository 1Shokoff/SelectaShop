"""Воркер рассылки: забирает письма из очереди и отправляет их.

Устройство цикла продиктовано одним ограничением: **нельзя держать
транзакцию БД открытой во время отправки письма**. Отправка идёт по сети
и занимает секунды, а с точки зрения PostgreSQL такая транзакция всё это
время «простаивает». У роли приложения выставлен
idle_in_transaction_session_timeout = 30s — соединение было бы разорвано
посреди работы.

Поэтому три отдельных шага:

  1. Захват: строки помечаются «отправляется», транзакция немедленно
     закрывается. Конкуренцию между воркерами снимает FOR UPDATE SKIP
     LOCKED — несколько процессов не возьмут одну строку.
  2. Отправка: без транзакции вообще.
  3. Запись результата: короткая транзакция на одну строку.

Гарантия доставки — «хотя бы один раз». Если процесс умрёт между шагами
2 и 3, строка останется помеченной и через stale_lock_seconds вернётся в
очередь, то есть письмо уйдёт повторно. Обратный порядок (сначала
отметить, потом отправить) давал бы риск потерять письмо совсем. Дубль
письма с подтверждением — неудобство; потерянное письмо — заблокированная
регистрация.
"""

from __future__ import annotations

import logging
import os
import secrets
import signal
import socket
import time
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from notifications.backends import DeliveryError, PermanentDeliveryError, get_backend
from notifications.models import OutboxMessage, OutboxStatus
from notifications.service import letter_from

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Отправляет письма из очереди. С --loop работает как постоянный сервис."

    def add_arguments(self, parser):
        parser.add_argument(
            "--loop",
            action="store_true",
            help="работать непрерывно (режим контейнера-воркера)",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help="сколько сообщений обработать за один проход",
        )

    def handle(self, *args, **options):
        self.worker_id = f"{socket.gethostname()}:{os.getpid()}"[:64]
        self.backend = get_backend()
        self.batch_size = options["limit"] or settings.WORKER["batch_size"]
        self._stopping = False

        # Контейнер останавливается сигналом TERM. Текущее письмо должно
        # быть дописано, новые не берутся.
        signal.signal(signal.SIGTERM, self._request_stop)
        signal.signal(signal.SIGINT, self._request_stop)

        self.stdout.write(
            f"  воркер {self.worker_id}, доставка: {settings.EMAIL['backend']}"
        )

        if not options["loop"]:
            sent, failed = self.run_once()
            self.stdout.write(f"  отправлено {sent}, с ошибкой {failed}")
            return

        interval = settings.WORKER["poll_interval_seconds"]
        while not self._stopping:
            self.reclaim_stale()
            sent, failed = self.run_once()
            if sent == 0 and failed == 0 and not self._stopping:
                # Пауза только на пустой очереди. Непустая разбирается
                # без задержек, иначе накопившиеся письма уходили бы
                # со скоростью одна пачка в интервал.
                self._sleep(interval)

        self.stdout.write("  воркер остановлен")

    # -- шаги цикла ---------------------------------------------------

    def run_once(self) -> tuple[int, int]:
        messages = self.claim()
        sent = failed = 0
        for message in messages:
            if self._deliver(message):
                sent += 1
            else:
                failed += 1
            if self._stopping:
                break
        return sent, failed

    def claim(self) -> list[OutboxMessage]:
        """Помечает пачку сообщений как «отправляется» и сразу фиксирует.

        SKIP LOCKED пропускает строки, уже захваченные другим воркером,
        вместо того чтобы ждать их освобождения.
        """
        now = timezone.now()
        with transaction.atomic():
            ids = list(
                OutboxMessage.objects.select_for_update(skip_locked=True)
                .filter(status=OutboxStatus.PENDING, next_attempt_at__lte=now)
                .order_by("next_attempt_at")
                .values_list("id", flat=True)[: self.batch_size]
            )
            if not ids:
                return []
            OutboxMessage.objects.filter(id__in=ids).update(
                status=OutboxStatus.SENDING, locked_at=now, locked_by=self.worker_id
            )

        return list(
            OutboxMessage.objects.filter(id__in=ids).select_related("recipient_email")
        )

    def _deliver(self, message: OutboxMessage) -> bool:
        try:
            letter = letter_from(message)
        except Exception as exc:  # noqa: BLE001
            # Тело не читается: неверный ключ шифрования либо повреждение.
            # Повторы не помогут.
            logger.exception("сообщение %s: не удалось развернуть тело", message.pk)
            self._give_up(message, f"тело сообщения не читается: {exc}")
            return False

        try:
            provider_id = self.backend.send(letter)
        except PermanentDeliveryError as exc:
            logger.error("сообщение %s: отказ без повторов: %s", message.pk, exc)
            self._give_up(message, str(exc))
            return False
        except DeliveryError as exc:
            logger.warning("сообщение %s: ошибка отправки: %s", message.pk, exc)
            self._schedule_retry(message, str(exc))
            return False
        except Exception as exc:  # noqa: BLE001
            logger.exception("сообщение %s: непредвиденная ошибка", message.pk)
            self._schedule_retry(message, repr(exc))
            return False

        # mark_sent заодно стирает тело: после отправки токен в базе
        # больше не нужен, а лишний срок жизни секрета не нужен тем более.
        message.mark_sent(provider_id)
        logger.info("сообщение %s отправлено (%s)", message.pk, message.template_key)
        return True

    def _schedule_retry(self, message: OutboxMessage, error: str) -> None:
        message.attempts += 1

        if message.attempts >= message.max_attempts:
            self._give_up(message, error)
            return

        base = settings.WORKER["retry_base_seconds"]
        ceiling = settings.WORKER["retry_max_seconds"]
        delay = min(base * (2 ** (message.attempts - 1)), ceiling)
        # Разброс нужен, чтобы накопившиеся за время недоступности релея
        # письма не ушли одновременно и не получили отказ по частоте.
        # Криптостойкий источник здесь не обязателен, но и не стоит ничего,
        # зато статический анализ не спотыкается о random.
        delay *= secrets.SystemRandom().uniform(0.8, 1.2)

        message.status = OutboxStatus.PENDING
        message.next_attempt_at = timezone.now() + timedelta(seconds=delay)
        message.last_error = error[:2000]
        message.locked_at = None
        message.locked_by = ""
        message.save(
            update_fields=[
                "attempts", "status", "next_attempt_at",
                "last_error", "locked_at", "locked_by",
            ]
        )

    def _give_up(self, message: OutboxMessage, error: str) -> None:
        message.status = OutboxStatus.DEAD
        message.last_error = error[:2000]
        message.locked_at = None
        message.locked_by = ""
        # Тело стирается и здесь: неотправленный токен хранить тем более
        # незачем — он всё равно истечёт.
        message.payload_ciphertext = None
        # attempts входит в список намеренно: счётчик увеличивается в
        # _schedule_retry непосредственно перед вызовом, и без сохранения
        # в базе оставалось бы значение на единицу меньше. При разборе
        # инцидента это вводило бы в заблуждение.
        message.save(
            update_fields=[
                "attempts", "status", "last_error", "locked_at",
                "locked_by", "payload_ciphertext",
            ]
        )

    def reclaim_stale(self) -> int:
        """Возвращает в очередь строки, застрявшие в состоянии «отправляется».

        Такое случается, если воркер был убит между отправкой и записью
        результата. Срок намеренно велик по сравнению с таймаутом SMTP:
        иначе обычная медленная отправка приводила бы к дублям.
        """
        horizon = timezone.now() - timedelta(
            seconds=settings.WORKER["stale_lock_seconds"]
        )
        returned = OutboxMessage.objects.filter(
            status=OutboxStatus.SENDING, locked_at__lt=horizon
        ).update(status=OutboxStatus.PENDING, locked_at=None, locked_by="")
        if returned:
            logger.warning("возвращено в очередь зависших сообщений: %s", returned)
        return returned

    # -- остановка ------------------------------------------------------

    def _request_stop(self, signum, frame):  # noqa: ARG002
        self.stdout.write("  получен сигнал остановки, завершаю текущую отправку")
        self._stopping = True

    def _sleep(self, seconds: float) -> None:
        """Сон, прерываемый сигналом остановки."""
        deadline = time.monotonic() + seconds
        while not self._stopping and time.monotonic() < deadline:
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))

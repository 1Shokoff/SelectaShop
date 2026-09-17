"""Очередь исходящих сообщений (transactional outbox).

Очередь живёт в PostgreSQL, а не во внешнем брокере. Две причины.

Первая — надёжность. Запись «пользователь создан» и запись «отправить ему
письмо» попадают в ОДНУ транзакцию. С внешним брокером возможна классическая
рассинхронизация: транзакция откатилась, а сообщение уже опубликовано, либо
наоборот — пользователь создан, а публикация потерялась между commit и publish.

Вторая — ресурсы. На VPS с 1 ГБ RAM отдельный брокер стоит 80-130 МБ,
которых нет. Пропускная способность outbox измеряется сотнями сообщений в
секунду, то есть превышает потребности магазина в тысячи раз.
"""

from __future__ import annotations

from django.db import models
from django.utils import timezone

from selectashop import crypto


class OutboxStatus(models.TextChoices):
    PENDING = "pending", "Ожидает отправки"
    SENDING = "sending", "Отправляется"
    SENT = "sent", "Отправлено"
    FAILED = "failed", "Ошибка, будет повтор"
    DEAD = "dead", "Отброшено после всех попыток"


class OutboxMessage(models.Model):
    channel = models.CharField(max_length=16, default="email")

    # Ссылка на адрес, а не копия адреса: персональные данные не
    # размножаются по таблицам, и удаление учётной записи забирает
    # неотправленные сообщения с собой.
    recipient_email = models.ForeignKey(
        "accounts.UserEmail", on_delete=models.CASCADE, related_name="outbox_messages"
    )

    template_key = models.CharField(max_length=64)

    # Контекст шаблона в зашифрованном виде. Шифруется потому, что внутри
    # лежит токен из письма. Хранить его здесь открытым текстом означало бы
    # обнулить весь смысл хранения хеша в verification_tokens: код лежал бы
    # в соседней таблице того же дампа.
    payload_ciphertext = models.BinaryField(null=True, blank=True)

    status = models.CharField(
        max_length=16, choices=OutboxStatus.choices, default=OutboxStatus.PENDING
    )
    attempts = models.SmallIntegerField(default=0)
    max_attempts = models.SmallIntegerField(default=5)
    next_attempt_at = models.DateTimeField(default=timezone.now)

    # Для выборки через FOR UPDATE SKIP LOCKED: несколько воркеров не
    # подерутся за одну строку.
    locked_at = models.DateTimeField(null=True, blank=True)
    locked_by = models.CharField(max_length=64, blank=True, default="")

    provider_message_id = models.CharField(max_length=255, blank=True, default="")
    last_error = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "исходящее сообщение"
        verbose_name_plural = "исходящие сообщения"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(status__in=[c[0] for c in OutboxStatus.choices]),
                name="outbox_status_valid",
            ),
        ]
        indexes = [
            # Частичный индекс: в него попадают только строки, ожидающие
            # отправки. Отправленные сообщения индекс не раздувают.
            models.Index(
                fields=["next_attempt_at"],
                condition=models.Q(status="pending"),
                name="outbox_ready_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.template_key} -> адрес #{self.recipient_email_id} ({self.status})"

    def set_payload(self, payload: dict) -> None:
        import json

        self.payload_ciphertext = crypto.get_cipher().encrypt(
            json.dumps(payload, ensure_ascii=False), context=crypto.AAD_OUTBOX_PAYLOAD
        )

    def get_payload(self) -> dict:
        import json

        if not self.payload_ciphertext:
            return {}
        return json.loads(
            crypto.get_cipher().decrypt(
                bytes(self.payload_ciphertext), context=crypto.AAD_OUTBOX_PAYLOAD
            )
        )

    def mark_sent(self, provider_message_id: str = "") -> None:
        """Отмечает отправку и СТИРАЕТ тело сообщения.

        Стирание обязательно: после отправки токен в payload больше не
        нужен, а его присутствие в базе — лишний срок жизни секрета.
        """
        self.status = OutboxStatus.SENT
        self.sent_at = timezone.now()
        self.provider_message_id = provider_message_id
        self.payload_ciphertext = None
        self.locked_at = None
        self.locked_by = ""
        self.save(
            update_fields=[
                "status", "sent_at", "provider_message_id",
                "payload_ciphertext", "locked_at", "locked_by",
            ]
        )

"""Плановая чистка. Запускается по расписанию.

Две задачи:
  * освободить адреса неподтверждённых регистраций старше суток,
  * удалить события безопасности старше срока хранения.

Первое закрывает захват чужого адреса: иначе злоумышленник регистрируется
на ваш email, не подтверждает его и навсегда блокирует вам регистрацию.
Второе выполняет требование не хранить персональные данные (а IP-адрес —
персональные данные) дольше необходимого.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand
from django.utils import timezone

from accounts.models import SecurityEvent, UserEmail, VerificationToken


class Command(BaseCommand):
    help = "Удаляет просроченные регистрации, токены и старые события."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="только показать, сколько записей будет удалено",
        )

    def handle(self, *args, **options):
        now = timezone.now()

        stale_emails = UserEmail.objects.filter(is_verified=False, expires_at__lt=now)
        stale_tokens = VerificationToken.objects.filter(expires_at__lt=now)

        if options["dry_run"]:
            self.stdout.write(f"  неподтверждённых адресов: {stale_emails.count()}")
            self.stdout.write(f"  просроченных токенов:     {stale_tokens.count()}")
            return

        tokens_removed, _ = stale_tokens.delete()
        emails_removed = UserEmail.objects.purge_expired()
        events_removed = SecurityEvent.purge_old()

        self.stdout.write(
            self.style.SUCCESS(
                f"  удалено: адресов {emails_removed}, токенов {tokens_removed}, "
                f"событий {events_removed}"
            )
        )

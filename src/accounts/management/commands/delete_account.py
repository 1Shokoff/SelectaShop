"""Удаление учётной записи. Два режима.

  обезличивание (по умолчанию) — боевой режим. Строка пользователя
      остаётся: на неё будут ссылаться заказы, которые нужно хранить для
      бухгалтерии. Адрес почты и логин удаляются физически, пароль
      делается непригодным. Адрес освобождается и может быть занят заново.

  --hard — полное удаление строки. Для боевого режима не годится: вместе
      с пользователем исчезнет история его заказов. Нужен для того, чтобы
      после проверки вернуть базу в исходное состояние.

Разрешение на полное удаление проверяется, а не выдаётся на слово: если у
пользователя есть заказы, команда откажет.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from accounts.models import Role, SecurityEvent, User, UserEmail, UserStatus
from accounts.validators import normalize_username


class Command(BaseCommand):
    help = "Удаляет учётную запись: обезличивание или полное удаление (--hard)."

    def add_arguments(self, parser):
        parser.add_argument("identifier", help="логин или адрес почты")
        parser.add_argument(
            "--hard",
            action="store_true",
            help="удалить строку полностью вместо обезличивания",
        )
        parser.add_argument(
            "--yes",
            action="store_true",
            help="не спрашивать подтверждения",
        )

    def handle(self, *args, **options):
        user = self._find(options["identifier"].strip())
        if user is None:
            raise CommandError(f"Пользователь {options['identifier']!r} не найден.")

        if user.status == UserStatus.ANONYMIZED and not options["hard"]:
            self.stdout.write("  Учётная запись уже обезличена.")
            return

        if user.role == Role.OWNER:
            remaining = User.objects.filter(role=Role.OWNER).exclude(pk=user.pk).count()
            if remaining == 0:
                raise CommandError(
                    "Это единственный владелец магазина. Удаление оставило бы "
                    "проект без administrator-доступа. Сначала назначьте другого: "
                    "manage.py grant_role <кто-то> owner --force"
                )

        mode = "ПОЛНОЕ УДАЛЕНИЕ" if options["hard"] else "обезличивание"
        email = user.primary_email
        self.stdout.write(
            f"  {user.username} (роль {user.role}, "
            f"почта {email.address if email else '—'}) — {mode}"
        )

        if not options["yes"]:
            answer = input("  Подтвердите, введя логин целиком: ").strip()
            if answer != user.username:
                raise CommandError("Не подтверждено, ничего не изменено.")

        if options["hard"]:
            self._hard_delete(user)
        else:
            self._anonymize(user)

    def _hard_delete(self, user: User) -> None:
        related = self._blocking_relations(user)
        if related:
            raise CommandError(
                "Полное удаление невозможно: с учётной записью связаны "
                f"{related}. Используйте обезличивание — оно сохранит эти "
                "записи, но уберёт данные человека."
            )

        username = user.username
        with transaction.atomic():
            # События безопасности ссылаются на пользователя через
            # SET NULL, поэтому сами они переживут удаление и останутся
            # в журнале уже без привязки.
            user.delete()

        self.stdout.write(self.style.SUCCESS(f"  {username}: строка удалена полностью"))

    def _anonymize(self, user: User) -> None:
        username = user.username
        with transaction.atomic():
            user.anonymize()
            SecurityEvent.objects.create(
                user=user,
                event_type=SecurityEvent.Type.USER_ANONYMIZED,
                metadata={"actor": "cli:delete_account", "was": username},
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"  {username}: обезличен, адрес почты освобождён, "
                f"логин заменён на {user.username}"
            )
        )

    @staticmethod
    def _blocking_relations(user: User) -> str:
        """Связи, из-за которых полное удаление недопустимо.

        Сейчас таких нет — заказы появятся на следующем этапе. Проверка
        заведена заранее, чтобы её не забыли добавить вместе с ними.
        """
        blocking = []
        for relation in ("orders",):
            manager = getattr(user, relation, None)
            if manager is not None:
                count = manager.count()
                if count:
                    blocking.append(f"{relation}: {count}")
        return ", ".join(blocking)

    @staticmethod
    def _find(identifier: str):
        if "@" in identifier:
            user_email = UserEmail.objects.find(identifier)
            return user_email.user if user_email else None
        return User.objects.filter(
            username_normalized=normalize_username(identifier)
        ).first()

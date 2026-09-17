"""Назначение роли пользователю.

Администраторов назначает владелец магазина и только из терминала.
Через веб роль не меняется никогда — по этой причине роль и не является
полем ни одной формы.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from accounts.models import Role, SecurityEvent, User, UserEmail, UserStatus
from accounts.validators import normalize_username


class Command(BaseCommand):
    help = "Меняет роль пользователя. Ищет по логину или адресу почты."

    def add_arguments(self, parser):
        parser.add_argument("identifier", help="логин или адрес почты")
        parser.add_argument(
            "role", choices=[Role.BUYER, Role.ADMIN, Role.OWNER], help="новая роль"
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="требуется для назначения роли owner",
        )

    def handle(self, *args, **options):
        identifier: str = options["identifier"].strip()
        new_role: str = options["role"]

        if new_role == Role.OWNER and not options["force"]:
            raise CommandError(
                "Назначение роли owner даёт полный контроль над магазином. "
                "Повторите команду с флагом --force, если это намеренно."
            )

        user = self._find(identifier)
        if user is None:
            raise CommandError(f"Пользователь {identifier!r} не найден.")

        if user.status == UserStatus.ANONYMIZED:
            raise CommandError("Учётная запись обезличена, роль менять нельзя.")

        old_role = user.role
        if old_role == new_role:
            self.stdout.write(f"  У пользователя {user.username} уже роль {new_role}.")
            return

        if new_role in (Role.ADMIN, Role.OWNER) and user.status != UserStatus.ACTIVE:
            raise CommandError(
                f"Состояние учётной записи — {user.status}. Административные "
                "права выдаются только активным пользователям с подтверждённой почтой."
            )

        with transaction.atomic():
            user.role = new_role
            user.save(update_fields=["role", "updated_at"])
            SecurityEvent.objects.create(
                user=user,
                event_type=SecurityEvent.Type.ROLE_CHANGED,
                metadata={"from": old_role, "to": new_role, "actor": "cli:grant_role"},
            )

        self.stdout.write(
            self.style.SUCCESS(f"  {user.username}: {old_role} -> {new_role}")
        )

    @staticmethod
    def _find(identifier: str):
        if "@" in identifier:
            user_email = UserEmail.objects.find(identifier)
            return user_email.user if user_email else None
        return User.objects.filter(
            username_normalized=normalize_username(identifier)
        ).first()

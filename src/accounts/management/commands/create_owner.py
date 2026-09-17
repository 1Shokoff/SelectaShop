"""Создание владельца магазина.

Только из терминала на сервере. У операции первичной настройки не должно
быть сетевой поверхности вообще: форма «создать первого администратора»
в вебе — это форма, которую будут искать и пробовать боты.
"""

from __future__ import annotations

import getpass
import sys

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from accounts.models import Role, SecurityEvent, User, UserEmail
from accounts.validators import normalize_email, validate_email_address, validate_username


class Command(BaseCommand):
    help = "Создаёт владельца магазина (роль owner) с подтверждённым адресом почты."

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True, help="логин владельца")
        parser.add_argument("--email", required=True, help="адрес почты владельца")
        parser.add_argument(
            "--password",
            help="пароль; если не указан, будет запрошен интерактивно "
                 "(предпочтительно: аргумент попадает в историю команд)",
        )

    def handle(self, *args, **options):
        username = options["username"].strip()
        email = normalize_email(options["email"])

        try:
            validate_username(username)
            validate_email_address(email)
        except ValidationError as exc:
            raise CommandError("; ".join(exc.messages)) from exc

        if User.objects.filter(username_normalized=username.lower()).exists():
            raise CommandError(f"Логин {username!r} уже занят.")
        if UserEmail.objects.find(email) is not None:
            raise CommandError("Этот адрес почты уже используется.")

        existing_owners = User.objects.filter(role=Role.OWNER).count()
        if existing_owners:
            self.stdout.write(
                self.style.WARNING(
                    f"  Внимание: владельцев уже {existing_owners}. "
                    "Создаётся ещё один."
                )
            )

        password = options.get("password")
        if not password:
            password = getpass.getpass("Пароль: ")
            if password != getpass.getpass("Пароль ещё раз: "):
                raise CommandError("Пароли не совпадают.")
        else:
            self.stdout.write(
                self.style.WARNING(
                    "  Пароль передан аргументом и остался в истории команд. "
                    "Очистите её либо смените пароль после входа."
                )
            )

        try:
            validate_password(password)
        except ValidationError as exc:
            raise CommandError("Пароль отклонён:\n  " + "\n  ".join(exc.messages)) from exc

        with transaction.atomic():
            user = User.objects.create_owner(
                username=username, password=password, email=email
            )
            SecurityEvent.objects.create(
                user=user,
                event_type=SecurityEvent.Type.ROLE_CHANGED,
                metadata={"to": Role.OWNER, "actor": "cli:create_owner"},
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"  Владелец создан: {user.username} (public_id={user.public_id})"
            )
        )
        if sys.stdout.isatty():
            self.stdout.write("  Адрес почты отмечен подтверждённым.")

"""Аутентификация по логину или адресу почты."""

from __future__ import annotations

from django.contrib.auth.backends import BaseBackend

from .models import User, UserEmail, UserStatus
from .validators import normalize_username


class EmailOrUsernameBackend(BaseBackend):
    """Единственный бэкенд аутентификации проекта.

    Заменяет стандартный ModelBackend, потому что тот умеет искать
    пользователя только по USERNAME_FIELD, а нам нужны два способа входа.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if not username or not password:
            return None

        identifier = username.strip()
        user = self._find_user(identifier)

        if user is None:
            # Хеширование фиктивного пароля выравнивает время ответа.
            # Без этого несуществующий логин обрабатывался бы заметно
            # быстрее существующего, и по времени ответа можно было бы
            # перебрать список реальных учётных записей.
            User().set_password(password)
            return None

        # Проверка пароля выполняется до проверки состояния — тоже ради
        # постоянства времени ответа.
        password_ok = user.check_password(password)
        if not password_ok:
            return None

        if user.status != UserStatus.ACTIVE:
            return None

        return user

    @staticmethod
    def _find_user(identifier: str):
        if "@" in identifier:
            # Поиск по слепому индексу: точное совпадение адреса.
            user_email = UserEmail.objects.find(identifier)
            if user_email is None or not user_email.is_verified:
                return None
            return user_email.user

        return User.objects.filter(
            username_normalized=normalize_username(identifier)
        ).first()

    def get_user(self, user_id):
        return User.objects.filter(pk=user_id).first()

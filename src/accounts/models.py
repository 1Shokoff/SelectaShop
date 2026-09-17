"""Пользователи, адреса почты, токены, согласия и журнал безопасности."""

from __future__ import annotations

import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models, transaction
from django.utils import timezone

from selectashop import crypto

from .validators import normalize_email, normalize_username


class Role(models.TextChoices):
    BUYER = "buyer", "Покупатель"
    ADMIN = "admin", "Администратор"
    OWNER = "owner", "Владелец"


class UserStatus(models.TextChoices):
    PENDING = "pending", "Ожидает подтверждения почты"
    ACTIVE = "active", "Активен"
    BLOCKED = "blocked", "Заблокирован"
    ANONYMIZED = "anonymized", "Обезличен"


class UserManager(BaseUserManager):
    """Создание учётных записей.

    Роль здесь не является параметром по умолчанию: любой создаваемый
    через регистрацию пользователь получает роль покупателя. Повышение
    роли выполняется отдельной операцией с записью в журнал.
    """

    def get_by_natural_key(self, username_normalized):
        return self.get(username_normalized=username_normalized)

    @transaction.atomic
    def register(self, *, username: str, password: str, email: str):
        """Регистрация покупателя вместе с неподтверждённым адресом почты.

        Обе записи создаются в одной транзакции: пользователь без адреса
        не имел бы способа подтвердить почту и остался бы мусором.
        """
        user = self.model(
            username=username.strip(),
            username_normalized=normalize_username(username),
            role=Role.BUYER,
            status=UserStatus.PENDING,
        )
        user.set_password(password)
        user.full_clean(exclude=["password", "last_login", "username_normalized"])
        user.save(using=self._db)

        user_email = UserEmail.objects.create_unverified(user=user, address=email, primary=True)
        return user, user_email

    @transaction.atomic
    def create_owner(self, *, username: str, password: str, email: str):
        """Владелец магазина. Создаётся только командой из терминала."""
        user = self.model(
            username=username.strip(),
            username_normalized=normalize_username(username),
            role=Role.OWNER,
            status=UserStatus.ACTIVE,
        )
        user.set_password(password)
        user.full_clean(exclude=["password", "last_login", "username_normalized"])
        user.save(using=self._db)

        UserEmail.objects.create_verified(user=user, address=email, primary=True)
        return user


class User(AbstractBaseUser):
    """Учётная запись.

    Без PermissionsMixin намеренно. Стандартный миксин приносит вторую
    систему авторизации — группы и точечные права — рядом с ролями.
    Две системы способны разойтись: у пользователя окажется право без
    соответствующей роли. Здесь источник правды один — поле role.
    """

    # Внешний идентификатор для адресов страниц. Последовательный id в URL
    # позволял бы перебором узнать число пользователей и адресоваться к
    # чужим записям.
    public_id = models.UUIDField(
        "публичный идентификатор", default=uuid.uuid4, unique=True, editable=False
    )

    # Как ввёл пользователь — для отображения.
    username = models.CharField("логин", max_length=32)

    # Нижний регистр — по нему проверяется уникальность и идёт поиск.
    # Отдельный столбец, а не функциональный индекс: Django для __iexact
    # генерирует UPPER(), и индекс по lower() просто не использовался бы,
    # превращая каждый вход в полное сканирование таблицы.
    username_normalized = models.CharField(max_length=32, unique=True, editable=False)

    role = models.CharField("роль", max_length=16, choices=Role.choices, default=Role.BUYER)
    status = models.CharField(
        "состояние", max_length=16, choices=UserStatus.choices, default=UserStatus.PENDING
    )

    anonymized_at = models.DateTimeField("обезличен", null=True, blank=True)
    created_at = models.DateTimeField("создан", auto_now_add=True)
    updated_at = models.DateTimeField("изменён", auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "username_normalized"
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = "пользователь"
        verbose_name_plural = "пользователи"
        constraints = [
            # Ограничения продублированы на уровне БД, а не только в коде:
            # запись мимо приложения тоже не сможет выставить чужую роль.
            models.CheckConstraint(
                condition=models.Q(role__in=[c[0] for c in Role.choices]),
                name="user_role_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=[c[0] for c in UserStatus.choices]),
                name="user_status_valid",
            ),
            models.CheckConstraint(
                condition=~models.Q(username_normalized=""),
                name="user_username_normalized_present",
            ),
        ]

    def __str__(self) -> str:
        return self.username

    def clean(self):
        super().clean()
        from .validators import validate_username

        validate_username(self.username)

    def save(self, *args, **kwargs):
        # Нормализованная форма пересчитывается всегда. Так эти два поля
        # физически не могут разойтись — даже если запись меняют в обход
        # обычного пути регистрации.
        self.username_normalized = normalize_username(self.username)
        super().save(*args, **kwargs)

    # --- Свойства, ожидаемые Django ------------------------------------

    @property
    def is_active(self) -> bool:
        return self.status == UserStatus.ACTIVE

    @property
    def is_staff(self) -> bool:
        return self.role in (Role.ADMIN, Role.OWNER) and self.is_active

    @property
    def is_superuser(self) -> bool:
        return self.role == Role.OWNER and self.is_active

    def has_perm(self, perm, obj=None) -> bool:
        return self.is_staff

    def has_module_perms(self, app_label) -> bool:
        return self.is_staff

    # --- Прикладные методы ---------------------------------------------

    @property
    def primary_email(self):
        return self.emails.filter(is_primary=True).first()

    @transaction.atomic
    def anonymize(self) -> None:
        """Обезличивание вместо удаления.

        Строка пользователя остаётся: на неё будут ссылаться заказы,
        которые нужно хранить для бухгалтерии. Всё, что позволяет
        опознать человека, удаляется физически.
        """
        self.emails.all().delete()
        self.tokens.all().delete()
        marker = f"deleted_{self.public_id.hex[:12]}"
        self.username = marker
        self.username_normalized = marker
        self.status = UserStatus.ANONYMIZED
        self.anonymized_at = timezone.now()
        self.set_unusable_password()
        self.save(
            update_fields=[
                "username", "username_normalized", "status",
                "anonymized_at", "password", "updated_at",
            ]
        )


class UserEmailManager(models.Manager):
    def _prepare(self, address: str) -> tuple[str, bytes, bytes]:
        from django.conf import settings as dj_settings

        from .validators import validate_email_address

        normalized = normalize_email(address)
        validate_email_address(normalized)
        cipher = crypto.get_cipher()
        return (
            normalized,
            cipher.encrypt(normalized, context=crypto.AAD_USER_EMAIL),
            crypto.blind_index(dj_settings.BLIND_INDEX_PEPPER, normalized),
        )

    def create_unverified(self, *, user, address: str, primary: bool = False):
        _, ciphertext, bidx = self._prepare(address)
        ttl = settings.ACCOUNTS["unverified_email_ttl_hours"]
        return self.create(
            user=user,
            email_ciphertext=ciphertext,
            email_bidx=bidx,
            key_version=settings.ENCRYPTION_KEY_VERSION,
            is_primary=primary,
            is_verified=False,
            expires_at=timezone.now() + timedelta(hours=ttl),
        )

    def create_verified(self, *, user, address: str, primary: bool = False):
        _, ciphertext, bidx = self._prepare(address)
        return self.create(
            user=user,
            email_ciphertext=ciphertext,
            email_bidx=bidx,
            key_version=settings.ENCRYPTION_KEY_VERSION,
            is_primary=primary,
            is_verified=True,
            verified_at=timezone.now(),
            expires_at=None,
        )

    def find(self, address: str):
        """Поиск по точному совпадению через слепой индекс.

        Поиск по части адреса невозможен по построению: в базе лежит
        шифротекст и необратимый отпечаток. Это осознанная цена за то,
        что утёкший дамп не содержит ни одного адреса.
        """
        from django.conf import settings as dj_settings

        normalized = normalize_email(address)
        bidx = crypto.blind_index(dj_settings.BLIND_INDEX_PEPPER, normalized)
        return self.filter(email_bidx=bidx).first()

    def purge_expired(self) -> int:
        """Удаляет просроченные неподтверждённые адреса.

        Без этого злоумышленник регистрируется на чужой адрес, не
        подтверждает его и навсегда блокирует владельцу регистрацию.
        """
        stale = self.filter(is_verified=False, expires_at__lt=timezone.now())
        user_ids = list(stale.values_list("user_id", flat=True))
        removed, _ = stale.delete()
        # Учётные записи, оставшиеся вообще без адреса, тоже бесполезны.
        User.objects.filter(
            id__in=user_ids, status=UserStatus.PENDING, emails__isnull=True
        ).delete()
        return removed


class UserEmail(models.Model):
    """Адрес электронной почты. Хранится только в зашифрованном виде."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="emails")

    # AES-256-GCM: nonce + шифротекст + тег аутентификации.
    email_ciphertext = models.BinaryField("зашифрованный адрес")

    # HMAC-SHA256 от нормализованного адреса. Единственный способ найти
    # пользователя по почте, не храня её открытым текстом.
    email_bidx = models.BinaryField("слепой индекс", max_length=32)

    key_version = models.SmallIntegerField("версия ключа", default=1)

    is_primary = models.BooleanField("основной", default=False)
    is_verified = models.BooleanField("подтверждён", default=False)
    verified_at = models.DateTimeField("подтверждён в", null=True, blank=True)

    # Срок жизни неподтверждённой записи.
    expires_at = models.DateTimeField("истекает", null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = UserEmailManager()

    class Meta:
        verbose_name = "адрес почты"
        verbose_name_plural = "адреса почты"
        constraints = [
            # Глобальная уникальность — и для подтверждённых, и для
            # ожидающих. Иначе двое могли бы «застолбить» один адрес.
            models.UniqueConstraint(fields=["email_bidx"], name="email_bidx_unique"),
            models.UniqueConstraint(
                fields=["user"],
                condition=models.Q(is_primary=True),
                name="one_primary_email_per_user",
            ),
            # Не более одного ожидающего подтверждения адреса на человека:
            # смена почты — это ровно одна запись в процессе.
            models.UniqueConstraint(
                fields=["user"],
                condition=models.Q(is_verified=False),
                name="one_pending_email_per_user",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(is_verified=True, verified_at__isnull=False)
                    | models.Q(is_verified=False, verified_at__isnull=True)
                ),
                name="verified_requires_timestamp",
            ),
        ]
        indexes = [
            models.Index(
                fields=["expires_at"],
                condition=models.Q(is_verified=False),
                name="pending_email_expiry_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"адрес #{self.pk} пользователя {self.user_id}"

    @property
    def address(self) -> str:
        """Расшифрованный адрес. Обращение стоит одной операции AES."""
        return crypto.get_cipher().decrypt(
            bytes(self.email_ciphertext), context=crypto.AAD_USER_EMAIL
        )

    def mark_verified(self) -> None:
        self.is_verified = True
        self.verified_at = timezone.now()
        self.expires_at = None
        self.save(update_fields=["is_verified", "verified_at", "expires_at"])


class TokenPurpose(models.TextChoices):
    EMAIL_VERIFY = "email_verify", "Подтверждение почты"
    PASSWORD_RESET = "password_reset", "Сброс пароля"


class VerificationToken(models.Model):
    """Одноразовый токен из письма.

    В базе хранится только HMAC токена. Утёкший дамп не позволит ни
    подтвердить чужую почту, ни сбросить чужой пароль.
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="tokens")
    email = models.ForeignKey(
        UserEmail, on_delete=models.CASCADE, related_name="tokens", null=True, blank=True
    )
    purpose = models.CharField(max_length=24, choices=TokenPurpose.choices)
    token_hash = models.BinaryField(max_length=32)

    expires_at = models.DateTimeField()
    attempts = models.SmallIntegerField(default=0)
    max_attempts = models.SmallIntegerField(default=5)
    consumed_at = models.DateTimeField(null=True, blank=True)

    created_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "токен подтверждения"
        verbose_name_plural = "токены подтверждения"
        constraints = [
            models.UniqueConstraint(fields=["token_hash"], name="token_hash_unique"),
            models.CheckConstraint(
                condition=models.Q(purpose__in=[c[0] for c in TokenPurpose.choices]),
                name="token_purpose_valid",
            ),
        ]
        indexes = [
            models.Index(
                fields=["user", "purpose"],
                condition=models.Q(consumed_at__isnull=True),
                name="active_token_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.get_purpose_display()} для пользователя {self.user_id}"

    @property
    def is_usable(self) -> bool:
        return (
            self.consumed_at is None
            and self.attempts < self.max_attempts
            and self.expires_at > timezone.now()
        )

    def consume(self) -> None:
        self.consumed_at = timezone.now()
        self.save(update_fields=["consumed_at"])


class UserConsent(models.Model):
    """Запись о согласии с юридическим документом.

    По 152-ФЗ доказывать наличие согласия обязан оператор, то есть
    владелец сайта. Эта таблица и есть доказательство.
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="consents")
    document_key = models.CharField("документ", max_length=64)
    document_version = models.CharField("версия", max_length=32)

    # SHA-256 текста документа на момент согласия. Без него запись
    # доказывала бы согласие с «версией 1.0» абстрактно; с ним —
    # с конкретным текстом, который нельзя подменить задним числом.
    document_hash = models.BinaryField(max_length=32)

    accepted_at = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True, default="")
    revoked_at = models.DateTimeField("отозвано", null=True, blank=True)

    class Meta:
        verbose_name = "согласие"
        verbose_name_plural = "согласия"
        indexes = [models.Index(fields=["user", "document_key"], name="consent_lookup_idx")]

    def __str__(self) -> str:
        return f"{self.document_key} v{self.document_version}"


class SecurityEvent(models.Model):
    """Журнал событий безопасности.

    Отсюда же считаются лимиты на неудачные входы и на отправку писем —
    отдельная таблица счётчиков не нужна.
    """

    class Type(models.TextChoices):
        REGISTERED = "registered", "Регистрация"
        EMAIL_VERIFIED = "email_verified", "Почта подтверждена"
        LOGIN_OK = "login_ok", "Успешный вход"
        LOGIN_FAILED = "login_failed", "Неудачный вход"
        LOGOUT = "logout", "Выход"
        PASSWORD_CHANGED = "password_changed", "Пароль изменён"
        PASSWORD_RESET_REQUESTED = "password_reset_requested", "Запрошен сброс пароля"
        ROLE_CHANGED = "role_changed", "Роль изменена"
        USER_BLOCKED = "user_blocked", "Пользователь заблокирован"
        USER_ANONYMIZED = "user_anonymized", "Учётная запись обезличена"

    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="security_events"
    )
    event_type = models.CharField(max_length=48, choices=Type.choices)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "событие безопасности"
        verbose_name_plural = "события безопасности"
        indexes = [
            models.Index(fields=["user", "-created_at"], name="event_by_user_idx"),
            models.Index(
                fields=["ip", "-created_at"],
                condition=models.Q(event_type="login_failed"),
                name="failed_login_by_ip_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.event_type} @ {self.created_at:%Y-%m-%d %H:%M}"

    @classmethod
    def purge_old(cls) -> int:
        """Чистка по сроку хранения.

        IP-адрес — персональные данные, держать его бессрочно нельзя.
        """
        horizon = timezone.now() - timedelta(
            days=settings.ACCOUNTS["security_event_retention_days"]
        )
        removed, _ = cls.objects.filter(created_at__lt=horizon).delete()
        return removed

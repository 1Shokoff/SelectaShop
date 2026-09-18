"""Регистрация, подтверждение почты, вход и восстановление доступа."""

from __future__ import annotations

import logging
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import (
    require_http_methods,
    require_POST,
    require_safe,
)

from notifications.service import RateLimited, enqueue
from selectashop import crypto

from . import ratelimit
from .forms import LoginForm, PasswordResetRequestForm, RegistrationForm, SetPasswordForm
from .legal import record_consent, required_documents
from .models import (
    SecurityEvent,
    TokenPurpose,
    User,
    UserEmail,
    UserStatus,
    VerificationToken,
)
from .validators import normalize_username

logger = logging.getLogger(__name__)


# =============================================================================
#  Регистрация
# =============================================================================

# HEAD присутствует во всех списках рядом с GET намеренно. По стандарту
# HEAD обязан работать везде, где работает GET: им пользуются системы
# мониторинга, проверки ссылок и часть поисковых роботов. Без него они
# получают 405 на каждой странице сайта.
@require_http_methods(["GET", "HEAD", "POST"])
def register(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        return redirect("accounts:profile")

    form = RegistrationForm(request.POST or None)

    if request.method == "POST":
        if ratelimit.registration_blocked(request):
            form.add_error(
                None,
                "С вашего адреса за последний час создано слишком много "
                "учётных записей. Попробуйте позже.",
            )
        elif form.is_valid():
            try:
                _register_or_notify(request, form.cleaned_data)
            except IntegrityError:
                # Гонка: логин или адрес заняли между проверкой формы и
                # вставкой. База поймала, показываем нейтральную ошибку.
                logger.warning("гонка при регистрации")
                form.add_error(None, "Не удалось завершить регистрацию. Попробуйте ещё раз.")
            else:
                # Ответ одинаков и для свободного, и для занятого адреса.
                # Иначе форма регистрации превращается в инструмент
                # проверки, есть ли у вас клиент с таким адресом.
                return render(request, "accounts/verify_sent.html")

    return render(request, "accounts/register.html", {"form": form})


@transaction.atomic
def _register_or_notify(request: HttpRequest, data: dict) -> None:
    """Создаёт учётную запись либо, если адрес занят, уведомляет владельца.

    Всё в одной транзакции вместе с постановкой письма в очередь: откат
    регистрации забирает письмо с собой, и наоборот.
    """
    address = data["email"]
    existing = UserEmail.objects.find(address)

    if existing is not None and _release_if_expired(existing):
        existing = None

    if existing is not None:
        # Адрес занят. Учётная запись не создаётся, но владелец адреса
        # узнаёт о попытке — а тот, кто пытался, не узнаёт ничего.
        _enqueue_quietly(
            user_email=existing,
            template_key="registration_attempt",
            context={},
        )
        return

    user, user_email = User.objects.register(
        username=data["username"], password=data["password1"], email=address
    )

    for key in required_documents():
        record_consent(
            user=user,
            key=key,
            ip=ratelimit.client_ip(request),
            user_agent=ratelimit.user_agent(request),
        )

    token = _issue_token(
        user=user,
        user_email=user_email,
        purpose=TokenPurpose.EMAIL_VERIFY,
        ttl_hours=settings.ACCOUNTS["email_verify_token_ttl_hours"],
        request=request,
    )

    _enqueue_quietly(
        user_email=user_email,
        template_key="email_verify",
        context={
            "username": user.username,
            "link": f"{settings.PUBLIC_BASE_URL}/accounts/verify/{token}/",
            "ttl_hours": settings.ACCOUNTS["email_verify_token_ttl_hours"],
        },
    )

    ratelimit.record(SecurityEvent.Type.REGISTERED, request=request, user=user)


def _release_if_expired(user_email: UserEmail) -> bool:
    """Освобождает адрес просроченной неподтверждённой регистрации.

    Без этого злоумышленник занимает чужой адрес, не подтверждает его и
    навсегда блокирует владельцу регистрацию. Плановая чистка делает то
    же самое, но здесь проверка нужна сразу: пользователь не должен ждать
    следующего запуска задачи.
    """
    if user_email.is_verified:
        return False
    if user_email.expires_at is None or user_email.expires_at > timezone.now():
        return False

    owner = user_email.user
    user_email.delete()
    if owner.status == UserStatus.PENDING and not owner.emails.exists():
        owner.delete()
    return True


def _issue_token(*, user, user_email, purpose, ttl_hours: int, request) -> str:
    """Создаёт одноразовый токен и возвращает его открытое значение.

    В базу попадает только HMAC: утёкший дамп не позволит ни подтвердить
    чужую почту, ни сбросить чужой пароль.
    """
    token = crypto.generate_token()
    VerificationToken.objects.create(
        user=user,
        email=user_email,
        purpose=purpose,
        token_hash=crypto.hash_token(settings.TOKEN_PEPPER, token),
        expires_at=timezone.now() + timedelta(hours=ttl_hours),
        created_ip=ratelimit.client_ip(request),
    )
    return token


def _enqueue_quietly(**kwargs) -> None:
    """Ставит письмо в очередь, проглатывая отказ по частоте.

    Превышение лимита не должно ломать регистрацию и не должно быть видно
    снаружи: иначе разное поведение опять выдаёт существование адреса.
    """
    try:
        enqueue(**kwargs)
    except RateLimited as exc:
        logger.info("письмо не поставлено в очередь: %s", exc)


# =============================================================================
#  Подтверждение адреса
# =============================================================================

@require_http_methods(["GET", "HEAD", "POST"])
def verify(request: HttpRequest, token: str) -> HttpResponse:
    """Подтверждение почты по ссылке из письма.

    Переход по ссылке (GET) только показывает страницу с кнопкой, а гасит
    токен нажатие (POST). Так сделано не ради красоты: корпоративные
    почтовые антивирусы «прокликивают» ссылки в письмах, проверяя их на
    вредоносность. Если бы токен гасился на GET, часть пользователей
    получала бы «ссылка устарела» ещё до того, как открыла письмо.
    """
    record = _find_token(token, TokenPurpose.EMAIL_VERIFY)

    if record is None or not record.is_usable:
        return render(
            request,
            "accounts/token_invalid.html",
            {
                "title": "Ссылка не действует",
                "message": "Ссылка подтверждения устарела или уже была использована. "
                           "Неподтверждённые регистрации удаляются через "
                           f"{settings.ACCOUNTS['unverified_email_ttl_hours']} ч, после чего "
                           "адрес освобождается и можно зарегистрироваться заново.",
            },
            status=410,
        )

    if request.method == "GET":
        return render(request, "accounts/verify_confirm.html", {"token": token})

    with transaction.atomic():
        user = record.user
        user_email = record.email

        record.consume()
        if user_email is not None and not user_email.is_verified:
            user_email.mark_verified()

        if user.status == UserStatus.PENDING:
            user.status = UserStatus.ACTIVE
            user.save(update_fields=["status", "updated_at"])

        ratelimit.record(SecurityEvent.Type.EMAIL_VERIFIED, request=request, user=user)

    return render(request, "accounts/verify_done.html")


def _find_token(token: str, purpose: str):
    if not token:
        return None
    digest = crypto.hash_token(settings.TOKEN_PEPPER, token)
    return VerificationToken.objects.filter(
        token_hash=digest, purpose=purpose, consumed_at__isnull=True
    ).select_related("user", "email").first()


# =============================================================================
#  Вход и выход
# =============================================================================

@require_http_methods(["GET", "HEAD", "POST"])
def login(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        return redirect("accounts:profile")

    form = LoginForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        identifier = form.cleaned_data["identifier"]
        candidate = _lookup_for_lockout(identifier)

        if ratelimit.login_blocked(request, candidate):
            form.add_error(
                None,
                "Слишком много неудачных попыток входа. "
                f"Повторите через {settings.ACCOUNTS['login_lockout_minutes']} мин.",
            )
        else:
            user = authenticate(
                request, username=identifier, password=form.cleaned_data["password"]
            )
            if user is not None:
                auth_login(request, user)
                ratelimit.record(SecurityEvent.Type.LOGIN_OK, request=request, user=user)
                return redirect(settings.LOGIN_REDIRECT_URL)

            ratelimit.record(
                SecurityEvent.Type.LOGIN_FAILED, request=request, user=candidate
            )
            # Один и тот же текст для неверного пароля, несуществующего
            # логина и неподтверждённой почты: иначе по ответу собирается
            # список существующих учётных записей.
            form.add_error(None, "Неверный логин, адрес почты или пароль.")

    return render(request, "accounts/login.html", {"form": form})


def _lookup_for_lockout(identifier: str):
    """Находит учётную запись для счётчика неудачных попыток.

    Результат наружу не попадает — он нужен только для того, чтобы
    считать попытки в том числе по конкретной записи, а не только по IP.
    """
    if "@" in identifier:
        user_email = UserEmail.objects.find(identifier)
        return user_email.user if user_email else None
    return User.objects.filter(
        username_normalized=normalize_username(identifier)
    ).first()


@require_POST
def logout(request: HttpRequest) -> HttpResponse:
    """Выход. Только POST: по ссылке-картинке с чужого сайта выйти нельзя."""
    if request.user.is_authenticated:
        ratelimit.record(SecurityEvent.Type.LOGOUT, request=request, user=request.user)
    auth_logout(request)
    return redirect(settings.LOGOUT_REDIRECT_URL)


# =============================================================================
#  Восстановление доступа
# =============================================================================

@require_http_methods(["GET", "HEAD", "POST"])
def password_reset_request(request: HttpRequest) -> HttpResponse:
    form = PasswordResetRequestForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        _send_reset_if_exists(request, form.cleaned_data["email"])
        # Ответ одинаков всегда, в том числе для несуществующего адреса.
        return render(request, "accounts/password_reset_sent.html")

    return render(request, "accounts/password_reset_request.html", {"form": form})


@transaction.atomic
def _send_reset_if_exists(request: HttpRequest, address: str) -> None:
    user_email = UserEmail.objects.find(address)
    if user_email is None or not user_email.is_verified:
        return

    user = user_email.user
    if user.status != UserStatus.ACTIVE:
        return

    ttl = settings.ACCOUNTS["password_reset_token_ttl_hours"]
    token = _issue_token(
        user=user,
        user_email=user_email,
        purpose=TokenPurpose.PASSWORD_RESET,
        ttl_hours=ttl,
        request=request,
    )
    _enqueue_quietly(
        user_email=user_email,
        template_key="password_reset",
        context={
            "username": user.username,
            "link": f"{settings.PUBLIC_BASE_URL}/accounts/password-reset/{token}/",
            "ttl_hours": ttl,
        },
    )
    ratelimit.record(
        SecurityEvent.Type.PASSWORD_RESET_REQUESTED, request=request, user=user
    )


@require_http_methods(["GET", "HEAD", "POST"])
def password_reset_confirm(request: HttpRequest, token: str) -> HttpResponse:
    record = _find_token(token, TokenPurpose.PASSWORD_RESET)

    if record is None or not record.is_usable:
        return render(
            request,
            "accounts/token_invalid.html",
            {
                "title": "Ссылка не действует",
                "message": "Ссылка восстановления устарела или уже была использована. "
                           "Запросите восстановление доступа заново.",
            },
            status=410,
        )

    form = SetPasswordForm(request.POST or None, user=record.user)

    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            user = record.user
            user.set_password(form.cleaned_data["password1"])
            user.save(update_fields=["password", "updated_at"])
            record.consume()

            # Прочие невыданные токены сброса гасятся: если письма
            # запрашивали несколько раз, старые ссылки не должны работать.
            VerificationToken.objects.filter(
                user=user,
                purpose=TokenPurpose.PASSWORD_RESET,
                consumed_at__isnull=True,
            ).update(consumed_at=timezone.now())

            if record.email is not None:
                _enqueue_quietly(
                    user_email=record.email,
                    template_key="password_changed",
                    context={"username": user.username},
                )

            ratelimit.record(
                SecurityEvent.Type.PASSWORD_CHANGED, request=request, user=user
            )

        # Смена пароля меняет хеш сеанса, поэтому все открытые сеансы
        # становятся недействительными — это поведение Django и оно нам
        # нужно: если доступ увели, чужой сеанс закрывается.
        return render(request, "accounts/password_reset_done.html")

    return render(
        request, "accounts/password_reset_confirm.html", {"form": form, "token": token}
    )


# =============================================================================
#  Личный кабинет
# =============================================================================

@login_required
@require_safe
def profile(request: HttpRequest) -> HttpResponse:
    user_email = request.user.primary_email
    return render(
        request,
        "accounts/profile.html",
        {
            "account": request.user,
            "email_address": user_email.address if user_email else None,
        },
    )

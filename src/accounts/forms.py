"""Формы регистрации, входа и восстановления доступа."""

from __future__ import annotations

from django import forms
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import User
from .validators import (
    normalize_email,
    normalize_username,
    validate_email_address,
    validate_username,
)


class RegistrationForm(forms.Form):
    username = forms.CharField(
        label="Логин",
        max_length=32,
        strip=True,
        widget=forms.TextInput(attrs={"autocomplete": "username", "autofocus": True}),
        help_text="Латинские буквы, цифры и символы . _ -. От 4 до 32 символов.",
    )
    email = forms.EmailField(
        label="Адрес электронной почты",
        max_length=254,
        widget=forms.EmailInput(attrs={"autocomplete": "email"}),
        help_text="На него придёт ссылка подтверждения и ваши покупки.",
    )
    password1 = forms.CharField(
        label="Пароль",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text="Не менее 10 символов. Не похожий на логин и не из словаря.",
    )
    password2 = forms.CharField(
        label="Пароль ещё раз",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )

    # Два отдельных согласия, а не одна галочка «согласен со всем»: закон
    # требует согласия конкретного и информированного, и объединённая
    # галочка эту планку проходит хуже.
    consent_pdn = forms.BooleanField(
        label="Я даю согласие на обработку персональных данных",
        required=True,
        error_messages={"required": "Без согласия на обработку данных регистрация невозможна."},
    )
    consent_terms = forms.BooleanField(
        label="Я принимаю пользовательское соглашение",
        required=True,
        error_messages={"required": "Необходимо принять пользовательское соглашение."},
    )

    def clean_username(self):
        value = self.cleaned_data["username"]
        validate_username(value)
        # Занятость логина скрывать смысла нет: логины видны на сайте.
        # А вот занятость адреса почты не раскрывается никогда — см. views.
        if User.objects.filter(username_normalized=normalize_username(value)).exists():
            raise ValidationError("Этот логин уже занят.")
        return value

    def clean_email(self):
        value = normalize_email(self.cleaned_data["email"])
        validate_email_address(value)
        return value

    def clean(self):
        cleaned = super().clean()
        p1, p2 = cleaned.get("password1"), cleaned.get("password2")

        if p1 and p2 and p1 != p2:
            self.add_error("password2", "Пароли не совпадают.")
            return cleaned

        if p1:
            # Валидаторы Django сверяют пароль с логином и почтой, поэтому
            # им передаётся заготовка пользователя.
            probe = User(username=cleaned.get("username", ""))
            try:
                validate_password(p1, probe)
            except ValidationError as exc:
                self.add_error("password1", exc)

        return cleaned


class LoginForm(forms.Form):
    identifier = forms.CharField(
        label="Логин или адрес почты",
        max_length=254,
        strip=True,
        widget=forms.TextInput(attrs={"autocomplete": "username", "autofocus": True}),
    )
    password = forms.CharField(
        label="Пароль",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )


class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField(
        label="Адрес электронной почты",
        max_length=254,
        widget=forms.EmailInput(attrs={"autocomplete": "email", "autofocus": True}),
    )

    def clean_email(self):
        # Здесь НЕ проверяется существование адреса и не применяется
        # чёрный список доменов: любой ответ, отличающийся для
        # существующего и несуществующего адреса, позволяет собирать
        # базу клиентов перебором.
        return normalize_email(self.cleaned_data["email"])


class SetPasswordForm(forms.Form):
    password1 = forms.CharField(
        label="Новый пароль",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password", "autofocus": True}),
        help_text="Не менее 10 символов.",
    )
    password2 = forms.CharField(
        label="Новый пароль ещё раз",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned = super().clean()
        p1, p2 = cleaned.get("password1"), cleaned.get("password2")

        if p1 and p2 and p1 != p2:
            self.add_error("password2", "Пароли не совпадают.")
            return cleaned

        if p1:
            try:
                validate_password(p1, self.user)
            except ValidationError as exc:
                self.add_error("password1", exc)

        return cleaned

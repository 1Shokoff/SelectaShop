"""Чтение юридических документов и фиксация согласий.

Тексты лежат файлами и версионируются git. В базу пишется ключ, версия и
SHA-256 текста. Хеш здесь принципиален: без него запись доказывала бы
согласие с «версией 1.0» абстрактно, а с ним — с конкретным текстом,
который нельзя подменить задним числом.
"""

from __future__ import annotations

from functools import lru_cache

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from selectashop.crypto import document_hash


@lru_cache(maxsize=8)
def load_document(key: str) -> tuple[str, str, bytes]:
    """Возвращает (версия, текст, sha256) документа.

    Результат кешируется: файлы меняются только при развёртывании.
    """
    meta = settings.LEGAL_DOCUMENTS.get(key)
    if meta is None:
        raise ImproperlyConfigured(f"неизвестный юридический документ {key!r}")

    path = settings.LEGAL_DOCUMENTS_DIR / meta["filename"]
    if not path.is_file():
        raise ImproperlyConfigured(
            f"не найден файл документа {path}. "
            "Проверьте [legal].documents_dir в конфигурации."
        )

    text = path.read_text(encoding="utf-8")
    return meta["version"], text, document_hash(text)


def record_consent(*, user, key: str, ip=None, user_agent: str = ""):
    """Фиксирует согласие пользователя с документом."""
    from .models import UserConsent

    version, _, digest = load_document(key)
    return UserConsent.objects.create(
        user=user,
        document_key=key,
        document_version=version,
        document_hash=digest,
        ip=ip,
        user_agent=(user_agent or "")[:255],
    )


def required_documents() -> tuple[str, ...]:
    """Документы, согласие с которыми обязательно при регистрации.

    Два отдельных согласия, а не одна галочка «согласен со всем»: закон
    требует согласия конкретного, информированного и сознательного, и
    объединённая галочка эту планку проходит хуже.
    """
    return ("pdn_consent", "terms_of_service")

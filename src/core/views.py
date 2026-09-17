"""Представления этапа 0: заглушка витрины и проверка живости."""

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_safe


@require_safe
def index(request: HttpRequest) -> HttpResponse:
    """Пустая витрина. Каталог появится на этапе 2."""
    return render(request, "core/index.html")


@require_safe
def healthz(request: HttpRequest) -> HttpResponse:
    """Проверка живости приложения.

    Намеренно не трогает базу данных и не раскрывает ни версии, ни
    состава окружения: ответ виден всем, кто дотянулся до сайта.
    Проверка доступности БД появится отдельной ручкой, закрытой
    от внешнего доступа, когда БД появится.
    """
    return HttpResponse("ok\n", content_type="text/plain; charset=utf-8")

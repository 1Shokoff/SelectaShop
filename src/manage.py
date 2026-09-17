#!/usr/bin/env python3
"""Утилита управления Django."""

import os
import sys


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "selectashop.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "Django не найден. Активирована ли виртуальная среда?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()

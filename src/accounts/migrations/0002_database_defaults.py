"""Значения по умолчанию на уровне самой базы данных.

Django выставляет default только в Python — в схеме столбец остаётся без
DEFAULT. Для роли это принципиально: запись, вставленная в обход
приложения (вручную из psql, будущим сервисом, скриптом миграции данных),
должна получать роль покупателя, а не полагаться на то, что вставляющий
не забыл указать её сам.

Вместе с CHECK-ограничением из первой миграции это даёт полный контроль
над полем роли на уровне хранилища: повысить себе права записью в базу
мимо приложения нельзя.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [("accounts", "0001_initial")]

    operations = [
        migrations.RunSQL(
            sql=[
                "ALTER TABLE accounts_user ALTER COLUMN role SET DEFAULT 'buyer';",
                "ALTER TABLE accounts_user ALTER COLUMN status SET DEFAULT 'pending';",
                "ALTER TABLE accounts_useremail ALTER COLUMN is_verified SET DEFAULT false;",
                "ALTER TABLE accounts_useremail ALTER COLUMN is_primary SET DEFAULT false;",
            ],
            reverse_sql=[
                "ALTER TABLE accounts_user ALTER COLUMN role DROP DEFAULT;",
                "ALTER TABLE accounts_user ALTER COLUMN status DROP DEFAULT;",
                "ALTER TABLE accounts_useremail ALTER COLUMN is_verified DROP DEFAULT;",
                "ALTER TABLE accounts_useremail ALTER COLUMN is_primary DROP DEFAULT;",
            ],
        ),
    ]

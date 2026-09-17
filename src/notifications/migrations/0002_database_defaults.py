"""Значение по умолчанию для статуса на уровне самой базы данных.

Django выставляет default только в Python. Строка, вставленная в обход
приложения, должна получать статус «ожидает отправки», а не полагаться на
внимательность того, кто её вставляет.

Отдельная миграция в своём приложении, а не общая с accounts: миграция
не должна изменять таблицы чужого приложения, иначе на чистой базе
порядок применения может поставить её раньше, чем эта таблица появится.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [("notifications", "0001_initial")]

    operations = [
        migrations.RunSQL(
            sql="ALTER TABLE notifications_outboxmessage ALTER COLUMN status SET DEFAULT 'pending';",
            reverse_sql="ALTER TABLE notifications_outboxmessage ALTER COLUMN status DROP DEFAULT;",
        ),
    ]

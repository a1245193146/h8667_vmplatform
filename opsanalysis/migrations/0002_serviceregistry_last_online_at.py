# 为 ServiceRegistry 增加"最近在线时间"字段（hand-written）

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('opsanalysis', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='serviceregistry',
            name='last_online_at',
            field=models.DateTimeField(blank=True, null=True, verbose_name='最近在线时间'),
        ),
    ]

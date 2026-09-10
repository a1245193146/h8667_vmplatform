# Generated for datastore fields on DiskResizeTask

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('resize', '0003_serverauthtask_trustsitetask'),
    ]

    operations = [
        migrations.AddField(
            model_name='diskresizetask',
            name='datastore_name',
            field=models.CharField(blank=True, default='', max_length=255, verbose_name='Datastore'),
        ),
        migrations.AddField(
            model_name='diskresizetask',
            name='datastore_free_gb',
            field=models.IntegerField(blank=True, null=True, verbose_name='申请时存储剩余(GB)'),
        ),
    ]

# Add AvDetection.resource_path（Defender 原始资源链留档）

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('antivirus', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='avdetection',
            name='resource_path',
            field=models.TextField(blank=True, default='', verbose_name='Defender原始资源链'),
        ),
    ]

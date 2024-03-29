# Generated by Django 4.0.6 on 2022-07-15 17:20

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('detection', '0006_alter_detection_device'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='device',
            name='device_type',
        ),
        migrations.AddField(
            model_name='detection',
            name='device_type',
            field=models.CharField(choices=[('PWS', 'Personal Web Server'), ('R', 'Router'), ('P', 'Printer'), ('C', 'Camera'), ('U', 'Unknown')], default='U', max_length=50),
        ),
        migrations.AddField(
            model_name='device',
            name='user',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='device_user', to=settings.AUTH_USER_MODEL, verbose_name='User'),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='detection',
            name='device',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='detection.device'),
        ),
        migrations.AlterField(
            model_name='detection',
            name='open_ports',
            field=models.CharField(max_length=100),
        ),
    ]

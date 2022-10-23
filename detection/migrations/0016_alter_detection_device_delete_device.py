# Generated by Django 4.0.6 on 2022-08-13 08:03

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('devices', '0001_initial'),
        ('detection', '0015_device_format'),
    ]

    operations = [
        migrations.AlterField(
            model_name='detection',
            name='device',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='devices.device'),
        ),
        migrations.DeleteModel(
            name='Device',
        ),
    ]
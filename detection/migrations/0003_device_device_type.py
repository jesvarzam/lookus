# Generated by Django 4.0.6 on 2022-07-13 10:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('detection', '0002_alter_device_detection_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='device_type',
            field=models.CharField(choices=[('PWS', 'Personal Web Server'), ('R', 'Router'), ('P', 'Printer'), ('C', 'Camera')], default='PWS', max_length=50),
        ),
    ]
# Generated by Django 4.0.6 on 2022-09-17 09:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('detection', '0017_alter_detection_device_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='detection',
            name='device_type',
            field=models.CharField(max_length=200),
        ),
    ]

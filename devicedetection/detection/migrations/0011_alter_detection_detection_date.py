# Generated by Django 4.0.6 on 2022-07-17 10:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('detection', '0010_alter_detection_detection_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='detection',
            name='detection_date',
            field=models.DateTimeField(default='17-Jul-2022-12-14-25'),
        ),
    ]

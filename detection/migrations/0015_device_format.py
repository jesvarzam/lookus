# Generated by Django 4.0.6 on 2022-07-30 09:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('detection', '0014_alter_detection_detection_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='format',
            field=models.CharField(choices=[('Único', 'Único'), ('Rango', 'Rango')], default='Único', max_length=10),
        ),
    ]
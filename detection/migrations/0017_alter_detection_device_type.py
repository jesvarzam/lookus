# Generated by Django 4.0.6 on 2022-09-11 10:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('detection', '0016_alter_detection_device_delete_device'),
    ]

    operations = [
        migrations.AlterField(
            model_name='detection',
            name='device_type',
            field=models.CharField(choices=[('Página web personal', 'Personal Web Server'), ('Router', 'Router'), ('Impresora', 'Printer'), ('Cámara', 'Camera'), ('Rango', 'Range'), ('Desconocido', 'Unknown')], default='Desconocido', max_length=50),
        ),
    ]

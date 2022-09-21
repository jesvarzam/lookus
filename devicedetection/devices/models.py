from django.db import models
from django.contrib.auth.models import User


class Device(models.Model):

    name = models.CharField(max_length=50)

    class Format(models.TextChoices):
        IP = 'Dirección IP'
        URL = 'Dirección URL'
        RANGO = 'Rango'
    
    format = models.CharField(
        max_length=20,
        choices=Format.choices,
        default=Format.IP
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='device_user', verbose_name='User')
    detected = models.BooleanField(default=False)

    def __str__(self):
        return self.name
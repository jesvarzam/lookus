from django.db import models
from django.contrib.auth.models import User
from datetime import datetime


class Device(models.Model):

    name = models.CharField(max_length=50)

    class Format(models.TextChoices):
        ÚNICO = 'Único'
        RANGO = 'Rango'
    
    format = models.CharField(
        max_length=10,
        choices=Format.choices,
        default=Format.ÚNICO
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='device_user', verbose_name='User')
    detected = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class Detection(models.Model):

    device = models.OneToOneField(Device, on_delete=models.CASCADE)

    class DeviceType(models.TextChoices):
        PERSONAL_WEB_SERVER = 'Página web personal'
        ROUTER = 'Router'
        PRINTER = 'Impresora'
        CAMERA = 'Cámara'
        UNKNOWN = 'Desconocido'
    
    device_type = models.CharField(
        max_length=50,
        choices=DeviceType.choices,
        default=DeviceType.UNKNOWN
    )

    detection_date = models.DateTimeField(default=datetime.now)
    open_ports = models.CharField(max_length=100)

    def __str__(self):
        return self.device.name + ' detection'
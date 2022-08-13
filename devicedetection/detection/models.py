from django.db import models
from datetime import datetime
from devices.models import Device


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
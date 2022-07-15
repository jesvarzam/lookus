from django.db import models
from datetime import datetime

class Device(models.Model):

    name = models.CharField(max_length=50)
    
    class DeviceType(models.TextChoices):
        PERSONAL_WEB_SERVER = 'PWS'
        ROUTER = 'R'
        PRINTER = 'P'
        CAMERA = 'C'
        UNKNOWN = 'U'
    
    device_type = models.CharField(
        max_length=50,
        choices=DeviceType.choices,
        default=DeviceType.UNKNOWN
    )

    def __str__(self):
        return self.name


class Detection(models.Model):

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    detection_date = models.DateTimeField(default=datetime.now)
    open_ports = models.JSONField()
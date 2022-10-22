from django.db import models
from datetime import datetime
from devices.models import Device


class Detection(models.Model):

    device = models.OneToOneField(Device, on_delete=models.CASCADE)

    device_type = models.CharField(max_length=200)

    detection_date = models.DateTimeField(default=datetime.now)
    open_ports = models.CharField(max_length=100)

    def __str__(self):
        return self.device.name + ' detection'
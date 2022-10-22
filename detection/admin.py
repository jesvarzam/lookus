from django.contrib import admin
from .models import Device, Detection

admin.site.register(Device)
admin.site.register(Detection)
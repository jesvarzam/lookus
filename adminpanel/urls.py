from django.urls import path
from django.contrib import admin
from .views import *

urlpatterns = [
    path('', adminpanel),
    path('django/', admin.site.urls),
    path('users/', users),
    path('users/<int:user_id>', user_details),
    path('users/remove/<int:user_id>', remove_user),
    path('devices/', devices),
    path('devices/remove_all', remove_all_devices),
    path('detections/', detections),
    path('detections/remove_all', remove_all_detections)
]
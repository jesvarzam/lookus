from django.urls import path
from .views import *

urlpatterns = [
    path('add/', add),
    path('list/', list_devices),
    path('remove/<int:device_id>/', remove),
    path('detect/<int:device_id>/', detect),
    path('results/<int:detection_id>/', results),
    path('pdf/<int:detection_id>/', pdf),
    path('training/', training)
]
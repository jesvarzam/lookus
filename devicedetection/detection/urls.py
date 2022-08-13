from django.urls import path
from .views import *

urlpatterns = [
    path('list/', list_detections),
    path('detect/<int:device_id>/', detect),
    path('results/<int:detection_id>/', results),
    path('pdf/<int:detection_id>/', pdf),
    path('training/', training)
]
from django.urls import path
from .views import *

urlpatterns = [
    path('', admin),
    path('users/', users),
    path('users/<int:user_id>', user_details),
    path('devices/', devices),
    path('detections/', detections)
]
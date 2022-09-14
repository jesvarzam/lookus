from django.urls import path
from .views import *

urlpatterns = [
    path('', admin),
    path('users/', users),
    path('users/<int:user_id>', user_details),
    path('users/remove/<int:user_id>', remove_user),
    path('devices/', devices),
    path('detections/', detections)
]
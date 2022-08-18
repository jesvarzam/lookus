from django.urls import path
from .views import *

urlpatterns = [
    path('add/', add),
    path('add_with_file/', add_with_file),
    path('list/', list_devices),
    path('remove/<int:device_id>/', remove),
    path('remove_all/', remove_all)
]
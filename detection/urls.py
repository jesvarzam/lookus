from django.urls import path
from .views import *

urlpatterns = [
    path('list/', list_detections),
    path('remove/<int:detection_id>/', remove),
    path('remove_all', remove_all),
    path('detect/<int:device_id>/', detect),
    path('results/<int:detection_id>/', results),
    path('pdf/<int:detection_id>/', pdf),
    path('training/', training),
    path('training_with_file/', training_with_file),
    path('training/json_example/', json_example),
    path('training/remove_dicc', remove_dicc)
]
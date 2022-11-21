from django.urls import path
from .views import *

urlpatterns = [
    path('', training),
    path('training_with_file/', training_with_file),
    path('json_example/', json_example),
    path('remove_dicc', remove_dicc)
]
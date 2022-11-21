from django.urls import path
from .views import *

urlpatterns = [
    path('', training),
    path('training_with_file/', training_with_file),
    path('json_example/', json_example),
    path('see_dicc/', see_dicc),
    path('remove_diccs', remove_diccs)
]
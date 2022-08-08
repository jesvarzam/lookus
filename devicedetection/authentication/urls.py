from django.urls import path
from authentication.views import *

urlpatterns = [
    path('sign_in', sign_in),
    path('sign_up', sign_up),
    path('log_out', log_out)
]
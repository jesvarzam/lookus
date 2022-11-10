from django.urls import path
from authentication.views import *

urlpatterns = [
    path('sign_in/', sign_in),
    path('sign_up/', sign_up),
    path('profile/', profile),
    path('profile/update_profile/', update_profile),
    path('profile/update_password/', update_password),
    path('log_out/', log_out)
]
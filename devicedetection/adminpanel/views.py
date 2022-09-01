from django.shortcuts import render, redirect
from django.http import FileResponse, Http404, HttpResponseForbidden
from django.http.response import HttpResponse
from django.contrib.auth.models import User
from devices.models import Device
from django.contrib import messages
from authentication.views import sign_in
from detection.models import Detection


def admin(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    elif not request.user.is_staff: return HttpResponseForbidden()
    return render(request, 'admin.html')


def users(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    elif not request.user.is_staff: return HttpResponseForbidden()
    return render(request, 'users.html', {'users': User.objects.all(), 'detections': Detection.objects.all()})    

def user_details(request, user_id):
    if not request.user.is_authenticated: return redirect(sign_in)
    elif not request.user.is_staff: return HttpResponseForbidden()
    user = User.objects.get(id=user_id)
    devices = Device.objects.get(user__id=user_id)
    detections = devices.detections
    return render(request, 'user_details.html', {'user': user, 'devices': devices, 'detections': detections})

from django.shortcuts import render, redirect
from django.http import HttpResponseForbidden
from django.contrib.auth.models import User
from devices.models import Device
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
    user_details = User.objects.get(id=user_id)
    devices = Device.objects.filter(user__id=user_id)
    detections = Detection.objects.filter(device__user__id=user_id)
    return render(request, 'user_details.html', {'user_details': user_details, 'devices': devices, 'detections': detections})


def devices(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    elif not request.user.is_staff: return HttpResponseForbidden()
    return render(request, 'devices.html', {'devices': Device.objects.all()})


def detections(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    elif not request.user.is_staff: return HttpResponseForbidden()
    return render(request, 'detections.html', {'detections': Detection.objects.all()})

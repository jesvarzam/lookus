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
    if len(request.GET) == 0: detections = Detection.objects.all()
    elif request.GET['filter'] == 'ip_detections': detections = Detection.objects.filter(device__user__id=request.user.id, device__format='Dirección IP')
    elif request.GET['filter'] == 'url_detections': detections = Detection.objects.filter(device__user__id=request.user.id, device__format='Dirección URL')
    elif request.GET['filter'] == 'open_ports_detections': detections = Detection.objects.filter(device__user__id=request.user.id).exclude(open_ports='No se han detectado puertos abiertos')
    elif request.GET['filter'] == 'no_open_ports_detections': detections = Detection.objects.filter(device__user__id=request.user.id, open_ports='No se han detectado puertos abiertos')
    return render(request, 'detections.html', {'detections': detections})
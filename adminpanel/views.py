from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseNotFound
from django.contrib.auth.models import User
from django.contrib import messages
from devices.models import Device
from authentication.views import sign_in
from detection.models import Detection
import os

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
    try:
        user_details = User.objects.get(id=user_id)
    except:
        return HttpResponseNotFound(HttpResponse('ERROR 404: No existe ningún usuario con ese id'))
    devices = Device.objects.filter(user__id=user_id)
    detections = Detection.objects.filter(device__user__id=user_id)
    return render(request, 'user_details.html', {'user_details': user_details, 'devices': devices, 'detections': detections})


def remove_user(request, user_id):
    if not request.user.is_authenticated: return redirect(sign_in)
    elif not request.user.is_staff: return HttpResponseForbidden()
    try:
        User.objects.get(id=user_id).delete()
    except:
        return HttpResponseNotFound(HttpResponse('ERROR 404: No existe ningún usuario con ese id'))
    messages.success(request, 'Usuario eliminado con éxito')
    return redirect(users)


def devices(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    elif not request.user.is_staff: return HttpResponseForbidden()
    if len(request.GET) == 0 or request.GET['filter'] == 'all_devices': devices = Device.objects.all()
    elif request.GET['filter'] == 'ip_devices': devices = Device.objects.filter(format='Dirección IP')
    elif request.GET['filter'] == 'url_devices': devices = Device.objects.filter(format='Dirección URL')
    elif request.GET['filter'] == 'range_devices': devices = Device.objects.filter(format='Rango de red')
    elif request.GET['filter'] == 'detected_devices': devices = Device.objects.filter(detected=True)
    elif request.GET['filter'] == 'undetected_devices': devices = Device.objects.filter(detected=False)

    filter = False
    if len(request.GET) > 0 and len(devices) == 0: filter = True
    return render(request, 'devices.html', {'devices': devices, 'filter': filter})


def remove_all_devices(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    if not request.user.is_staff: return HttpResponseForbidden()
    all_devices = Device.objects.all()

    for device in all_devices:
        if device.detected:
            html_path = 'detection/templates/reports/{}.html'.format(device.detection.id)
            pdf_path = 'detection/templates/reports/{}.pdf'.format(device.detection.id)
            temp_html_path = 'detection/templates/reports/{}pdf.html'.format(device.detection.id)
    
            if os.path.exists(html_path):
                os.remove(html_path)
            
            if os.path.exists(pdf_path):
                os.remove(pdf_path)
            
            if os.path.exists(temp_html_path):
                os.remove(temp_html_path)

        device.delete()
    
    messages.success(request, 'Dispositivos borrados correctamente')
    return redirect(devices)
    

def detections(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    elif not request.user.is_staff: return HttpResponseForbidden()
    if len(request.GET) == 0 or request.GET['filter'] == 'all_detections': detections = Detection.objects.all()
    elif request.GET['filter'] == 'ip_detections': detections = Detection.objects.filter(device__format='Dirección IP')
    elif request.GET['filter'] == 'url_detections': detections = Detection.objects.filter(device__format='Dirección URL')
    elif request.GET['filter'] == 'range_detections': detections = Detection.objects.filter(device__format='Dirección URL')
    elif request.GET['filter'] == 'open_ports_detections': detections = Detection.objects.all().exclude(open_ports='No se han detectado puertos abiertos')
    elif request.GET['filter'] == 'no_open_ports_detections': detections = Detection.objects.filter(open_ports='No se han detectado puertos abiertos')

    filter = False
    if len(request.GET) > 0 and len(detections) == 0: filter = True
    return render(request, 'detections.html', {'detections': detections, 'filter': filter})


def remove_all_detections(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    if not request.user.is_staff: return HttpResponseForbidden()
    all_detections = Detection.objects.all()

    for d in all_detections:
        html_path = 'detection/templates/reports/{}.html'.format(d.id)
        pdf_path = 'detection/templates/reports/{}.pdf'.format(d.id)
        temp_html_path = 'detection/templates/reports/{}pdf.html'.format(d.id)
    
        if os.path.exists(html_path):
            os.remove(html_path)
        
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
        
        if os.path.exists(temp_html_path):
            os.remove(temp_html_path)
        
        device = Device.objects.get(detection=d.id)
        device.detected = False
        device.save()
        d.delete()
    
    messages.success(request, 'Detecciones borradas correctamente')
    return redirect(detections)
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from .utils import single_device_detection, create_table_html
from .forms import DetectionForm
from .models import Device, Detection
from authentication.views import *
from django.contrib.auth.models import User
from django.contrib import messages
import os

def add(request):
    if request.method == 'POST':
        form = DetectionForm(request.POST)
        if form.is_valid():

            d = Device(name=form.cleaned_data['name'], user=User.objects.get(id=request.user.id))
            d.save()
            messages.success(request, 'Dispositivo añadido correctamente')
            return redirect(index)
        
        else:
            return render(request, 'add.html', {'form': form})
    
    else:
        form = DetectionForm()
    return render(request, 'add.html', {'form': form})


def list_devices(request):

    devices = Device.objects.filter(user=User.objects.get(id=request.user.id))
    return render(request, 'list.html', {'devices': devices})


def remove(request, device_id):

    device = Device.objects.get(id=device_id)
    
    if device.detected:
        os.remove('detection/templates/reports/{}.html'.format(device.detection.id))
        
    device.delete()
    messages.success(request, 'Dispositivo borrado correctamente')
    return redirect(index)


def detect(request, device_id):

    device_to_detect = Device.objects.get(id=device_id)
    res = single_device_detection(device_to_detect)

    if 'Not active' in res:
        messages.error(request, 'El dispositivo {} no está activo, por lo que no se puede detectar'.format(device_to_detect.name))
        return redirect(list_devices)
    
    if 'No open ports' in res:
        messages.error(request, 'El dispositivo {} no tiene puertos abiertos, por lo que no se puede detectar'.format(device_to_detect.name))
        return redirect(list_devices)
    
    detection = Detection(device=device_to_detect, device_type=res['Device type'], open_ports=res['Open ports'])
    detection.save()
    messages.success(request, 'El dispositivo {} se ha detectado correctamente'.format(device_to_detect.name))
    device_to_detect.detected = True
    device_to_detect.save()
    create_table_html([device_to_detect.name, detection.open_ports, detection.device_type], detection)

    return redirect(list_devices)


def results(request, detection_id):
    return render(request, 'reports/{}.html'.format(detection_id))

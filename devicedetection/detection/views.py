from django.shortcuts import render, redirect
from django.http import FileResponse, Http404
from .utils import single_device_detection, create_table_html
from .forms import DetectionForm
from .models import Device, Detection
from authentication.views import *
from django.contrib.auth.models import User
from django.contrib import messages
import os, pdfkit, subprocess, validators, re

def save_http_info(device):

    if not validators.url(device):
            http_device = 'http://' + device
    output = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
    output = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', output)
    output = output.replace('%', '')
    return output.split(',')

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
    html_path = 'detection/templates/reports/{}.html'.format(device.detection.id)
    pdf_path = 'detection/templates/reports/{}.pdf'.format(device.detection.id)
    
    if device.detected:

        if os.path.exists(html_path):
            os.remove(html_path)
        
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
        
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

    http_info = 'El dispositivo no tiene un servidor HTTP, por lo que no se ha podido obtener información'

    if '80' in detection.open_ports:
        http_info = save_http_info(device_to_detect.name)
    
    create_table_html([device_to_detect.name, detection.open_ports, detection.device_type, http_info], detection)

    return redirect(list_devices)


def results(request, detection_id):
    return render(request, 'reports/{}.html'.format(detection_id))


def pdf(request, detection_id):
    pdfkit.from_file('detection/templates/reports/{}.html'.format(str(detection_id)), 'detection/templates/reports/{}.pdf'.format(str(detection_id)))
    try:
        return FileResponse(open('detection/templates/reports/{}.pdf'.format(str(detection_id)), 'rb'), content_type='application/pdf')
    except FileNotFoundError:
        raise Http404()
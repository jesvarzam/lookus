from django.shortcuts import render, redirect
from django.http import FileResponse, Http404
from .utils import single_device_detection, create_table_html, range_device_detection, train_devices
from .forms import TrainingForm
from .models import Device, Detection
from authentication.views import *
from devices.views import list_devices
from django.contrib.auth.models import User
from django.contrib import messages
import os, pdfkit, subprocess, validators, re


def save_http_info(device):

    http_device = device

    if not validators.url(device):
        http_device = 'http://' + device
    
    output = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
    output = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', output)
    output = output.replace('%', '').split('\n')
    output = ', '.join(output).split(', ')[:-1]
    return list(set(output))


def detect(request, device_id):

    device_to_detect = Device.objects.get(id=device_id)

    if device_to_detect.format == 'Único':
        res = single_device_detection(device_to_detect)
    
    else:
        res = range_device_detection(device_to_detect)

        for r in res:

            print('Guardando dispositivo ' + str(r['Device']))

            loop_device = Device(name=r['Device'], user=User.objects.get(id=request.user.id))
            loop_device.detected = True
            loop_device.save()

            if 'No open ports' in r:
                detection = Detection(device=loop_device, device_type='Desconocido', open_ports='Ninguno')
                detection.save()
                messages.success(request, 'Detección del dispositivo {} finalizada'.format(r['Device']))
                create_table_html([r['Device'], detection.open_ports, detection.device_type, 'No es posible obtener información'], detection)
                
            else:
                detection = Detection(device=loop_device, device_type=r['Device type'], open_ports=r['Open ports'])
                detection.save()
                messages.success(request, 'El dispositivo {} se ha detectado correctamente'.format(device_to_detect.name))
                http_info = 'El dispositivo no tiene un servidor HTTP, por lo que no se ha podido obtener información'

                if '80' in detection.open_ports:
                    http_info = save_http_info(r['Device'])
                
                create_table_html([r['Device'], detection.open_ports, detection.device_type, http_info], detection)
        
        device_to_detect.delete()
            
        return redirect(list_devices)
         
    
    if 'No open ports' in res:
        detection = Detection(device=device_to_detect, device_type='Desconocido', open_ports='Ninguno')
        detection.save()
        messages.success(request, 'Detección del dispositivo {} finalizada'.format(device_to_detect.name))
        device_to_detect.detected = True
        device_to_detect.save()

        create_table_html([device_to_detect.name, detection.open_ports, detection.device_type, 'No es posible obtener información'], detection)
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

    pdf_path = 'detection/templates/reports/{}.pdf'.format(str(detection_id))

    if os.path.exists(pdf_path):
        return FileResponse(open(pdf_path, 'rb'), content_type='application/pdf')
    
    pdfkit.from_file('detection/templates/reports/{}pdf.html'.format(str(detection_id)), pdf_path)
    try:
        return FileResponse(open(pdf_path, 'rb'), content_type='application/pdf')
    except FileNotFoundError:
        raise Http404()

    
def training(request):
    if request.method == 'POST':
        form = TrainingForm(request.POST)
        if form.is_valid():

            devices = {}
            
            web_servers = form.cleaned_data['web_servers'].strip().split(',')
            routers = form.cleaned_data['routers'].strip().split(',')
            printers = form.cleaned_data['printers'].strip().split(',')
            cameras = form.cleaned_data['cameras'].strip().split(',')

            devices['web_dicc.txt'] = web_servers
            devices['router_dicc.txt'] = routers
            devices['printer_dicc.txt'] = printers
            devices['camera_dicc.txt'] = cameras

            train_devices(devices, request.user)

            return redirect(index)
    
    else:
        form = TrainingForm()
    return render(request, 'training.html', {'form':form})
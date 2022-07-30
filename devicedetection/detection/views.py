from django.shortcuts import render, redirect
from django.http import FileResponse, Http404

from .utils import checkRangeFormat, single_device_detection, create_table_html, range_device_detection
from .forms import DetectionForm
from .models import Device, Detection
from authentication.views import *
from django.contrib.auth.models import User
from django.contrib import messages
import os, pdfkit, subprocess, validators, re

def save_http_info(device):

    http_device = device

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

            if checkRangeFormat(form.cleaned_data['name']):
                d = Device(name=form.cleaned_data['name'], format='Rango', user=User.objects.get(id=request.user.id))
            
            else:
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
    messages.success(request, 'Dispositivo borrado correctamente')
    return redirect(list_devices)


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
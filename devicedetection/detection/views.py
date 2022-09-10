from django.shortcuts import render, redirect
from django.http import FileResponse, Http404
from django.http.response import HttpResponse
from .utils import single_device_detection, create_table_html, range_device_detection, train_devices
from .forms import TrainingForm
from .models import Device, Detection
from authentication.views import *
from devices.views import checkFormats, list_devices
from django.contrib.auth.models import User
from django.contrib import messages
import os, pdfkit, subprocess, validators, re, json, shutil


def list_detections(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    return render(request, 'list_detections.html', {'detections': Detection.objects.all().filter(device__user__id=request.user.id)})


def remove(request, detection_id):
    if not request.user.is_authenticated: return redirect(sign_in)
    
    detection = Detection.objects.get(id=detection_id)
    device = Device.objects.get(detection=detection)

    html_path = 'detection/templates/reports/{}.html'.format(device.detection.id)
    pdf_path = 'detection/templates/reports/{}.pdf'.format(device.detection.id)
    temp_html_path = 'detection/templates/reports/{}pdf.html'.format(device.detection.id)

    if os.path.exists(html_path):
        os.remove(html_path)
    
    if os.path.exists(pdf_path):
        os.remove(pdf_path)
    
    if os.path.exists(temp_html_path):
        os.remove(temp_html_path)

    detection.delete()
    device.detected = False
    device.save()

    messages.success(request, 'Detección borrada satisfactoriamente')
    return redirect(list_detections)


def save_http_info(device):

    http_device = device

    if not validators.url(device):
        http_device = 'http://' + device
    
    output = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
    output = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', output)
    output = output.replace('%', '').split('\n')
    output = ', '.join(output).split(', ')[:-1]
    return list(set(output))

def save_https_info(device):

    https_device = device

    if not validators.url(device):
        https_device = 'https://' + device
    
    output = subprocess.run(['whatweb', https_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
    output = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', output)
    output = output.replace('%', '').split('\n')
    output = ', '.join(output).split(', ')[:-1]
    return list(set(output))


def detect(request, device_id):
    if not request.user.is_authenticated: return redirect(sign_in)

    if request.method == 'POST':

        use_own_dicc = request.POST.get("own_dicc", None)=="own_dicc_true"
        dictionary_path_exists = "detection/diccs/" + str(request.user.username) + str(request.user.id)
        print(dictionary_path_exists)
        if use_own_dicc and not os.path.exists(dictionary_path_exists):
            print('te he pillao')
            messages.error(request, 'No tienes un diccionario propio creado. Pulsa en el menú "Entrenar diccionario de datos" situado a la izquierda para añadirlo')
            return redirect(list_devices)

        device_to_detect = Device.objects.get(id=device_id)

        if device_to_detect.format == 'Dirección IP' or device_to_detect.format == 'Dirección URL':
            res = single_device_detection(device_to_detect, request.user, request.POST.get("own_dicc", None)=="own_dicc_true")
        
        else:
            res = range_device_detection(device_to_detect, request.user, request.POST.get("own_dicc", None)=="own_dicc_true")

            for r in res:

                print('Guardando dispositivo ' + str(r['Device']))

                loop_device = Device(name=r['Device'], user=User.objects.get(id=request.user.id))
                loop_device.detected = True
                loop_device.save()

                if 'No open ports' in r:
                    detection = Detection(device=loop_device, device_type='Desconocido', open_ports='No se han detectado puertos abiertos')
                    detection.save()
                    http_info = 'El dispositivo no tiene un servidor HTTP, por lo que no se ha podido obtener información'
                    create_table_html([r['Device'], detection.open_ports, detection.device_type, http_info], detection)
                    
                else:
                    detection = Detection(device=loop_device, device_type=r['Device type'], open_ports=r['Open ports'])
                    detection.save()
                    http_info = 'El dispositivo no tiene un servidor HTTP, por lo que no se ha podido obtener información'

                    if '80' in detection.open_ports or '443' in detection.open_ports:
                        whatweb = r['Whatweb']
                        whatweb = whatweb.replace('%', '').split('\n')
                        whatweb = list(set(', '.join(whatweb).split(', ')[:-1]))
                        http_info = whatweb

                    if detection.open_ports != '':
                        create_table_html([r['Device'], detection.open_ports, detection.device_type, http_info], detection)
            
            device_to_detect.delete()
            messages.success(request, 'El dispositivo {} se ha detectado correctamente'.format(device_to_detect.name))    
            return redirect(list_devices)
            
        
        if 'No open ports' in res:
            detection = Detection(device=device_to_detect, device_type='Desconocido', open_ports='No se han detectado puertos abiertos')
            detection.save()
            messages.success(request, 'El dispositivo {} se ha detectado correctamente'.format(device_to_detect.name))
            device_to_detect.detected = True
            device_to_detect.save()
            http_info = 'El dispositivo no tiene un servidor HTTP, por lo que no se ha podido obtener información'

            create_table_html([device_to_detect.name, detection.open_ports, detection.device_type, http_info], detection)
            return redirect(list_devices)

        
        detection = Detection(device=device_to_detect, device_type=res['Device type'], open_ports=res['Open ports'])
        detection.save()
        messages.success(request, 'El dispositivo {} se ha detectado correctamente'.format(device_to_detect.name))
        device_to_detect.detected = True
        device_to_detect.save()

        http_info = 'El dispositivo no tiene un servidor HTTP, por lo que no se ha podido obtener información'
        print(detection.open_ports)

        ports_open = []
        temp_ports_open = detection.open_ports.split(', ')
        for p in temp_ports_open:
            ports_open.append(int(p))

        if 80 in ports_open or 443 in ports_open:
            whatweb = res['Whatweb']
            whatweb = whatweb.replace('%', '').split('\n')
            whatweb = list(set(', '.join(whatweb).split(', ')[:-1]))
            http_info = whatweb

        create_table_html([device_to_detect.name, detection.open_ports, detection.device_type, http_info], detection)

        return redirect(list_devices)
    
    else:
        return redirect(list_devices)


def results(request, detection_id):
    if not request.user.is_authenticated: return redirect(sign_in)
    return render(request, 'reports/{}.html'.format(detection_id))


def pdf(request, detection_id):
    if not request.user.is_authenticated: return redirect(sign_in)

    pdf_path = 'detection/templates/reports/{}.pdf'.format(str(detection_id))

    if os.path.exists(pdf_path):
        return FileResponse(open(pdf_path, 'rb'), content_type='application/pdf')
    
    pdfkit.from_file('detection/templates/reports/{}pdf.html'.format(str(detection_id)), pdf_path)
    try:
        return FileResponse(open(pdf_path, 'rb'), content_type='application/pdf')
    except FileNotFoundError:
        raise Http404()

    
def training(request):

    if not request.user.is_authenticated: return redirect(sign_in)

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

            messages.success('Diccionario de datos entrenado correctamente')
            return redirect(training)
    
        else:
            form = TrainingForm()
    return render(request, 'training.html')


def training_with_file(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    
    if request.method == 'POST' and request.FILES['training_file']:
        devices_json = json.loads(request.FILES['training_file'].read().decode())

        for k in devices_json:
            devices = devices_json[k]
        
            if (not checkFormats(devices) and len(devices) > 0) or k not in ['Página web personal', 'Router', 'Impresora', 'Cámara']:
                messages.error(request, """El archivo contiene algún dispositivo en formato incorrecto. 
                Por favor, comprueba que el formato de todos los dispositivos es correcto y vuelve a intentarlo.""")
                return redirect(training)
        
        devices = {}
        devices['web_dicc.txt'] = devices_json['Página web personal']
        devices['router_dicc.txt'] = devices_json['Router']
        devices['printer_dicc.txt'] = devices_json['Impresora']
        devices['camera_dicc.txt'] = devices_json['Cámara']

        train_devices(devices, request.user)
        
        messages.success(request, 'Modelo de datos entrenado correctamente')
        return redirect(training)
    else:
        return redirect(training)

    
def json_example(request):
    json_path = 'detection/templates/example.json'
    response = HttpResponse(open(json_path, 'rb'), content_type='application/json')
    response['Content-Disposition'] = "attachment; filename=%s" % 'example.json'
    return response


def remove_dicc(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    dicc_path = 'detection/diccs/' + str(request.user.username) + str(request.user.id)
    if not os.path.exists(dicc_path):
        messages.error(request, 'No tienes ningún diccionario de datos añadido, completa el formulario situado en esta página para crear uno')
        return redirect(training)
    shutil.rmtree(dicc_path)
    messages.success(request, 'Diccionario de datos eliminado correctamente')
    return redirect(training)
from django.shortcuts import render, redirect
from django.http import FileResponse, Http404
from django.http.response import HttpResponse, HttpResponseForbidden, HttpResponseNotFound
from .utils import single_device_detection, create_table_html, create_table_html_for_range, range_device_detection, train_devices
from .forms import TrainingForm
from .models import Device, Detection
from authentication.views import *
from devices.views import checkFormats, list_devices
from django.contrib import messages
import os, pdfkit, subprocess, validators, re, json, shutil


def list_detections(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    if len(request.GET) == 0: detections = Detection.objects.filter(device__user__id=request.user.id)
    elif request.GET['filter'] == 'ip_detections': detections = Detection.objects.filter(device__user__id=request.user.id, device__format='Dirección IP')
    elif request.GET['filter'] == 'url_detections': detections = Detection.objects.filter(device__user__id=request.user.id, device__format='Dirección URL')
    elif request.GET['filter'] == 'open_ports_detections': detections = Detection.objects.filter(device__user__id=request.user.id).exclude(open_ports='No se han detectado puertos abiertos')
    elif request.GET['filter'] == 'no_open_ports_detections': detections = Detection.objects.filter(device__user__id=request.user.id, open_ports='No se han detectado puertos abiertos')
    return render(request, 'list_detections.html', {'detections': detections})


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


def remove_all(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    detections = Detection.objects.filter(device__user__id=request.user.id)

    for d in detections:
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

        http_info = 'El dispositivo no tiene un servidor HTTP, por lo que no se ha podido obtener información'

        use_own_dicc = request.POST.get("own_dicc", None)=="own_dicc_true"
        dictionary_path_exists = "detection/diccs/" + str(request.user.username) + str(request.user.id)
        if use_own_dicc and not os.path.exists(dictionary_path_exists):
            messages.error(request, 'No tienes un diccionario propio creado. Pulsa en el menú "Entrenar diccionario de datos" situado a la izquierda para añadirlo')
            return redirect(list_devices)

        try:
            device_to_detect = Device.objects.get(id=device_id)
        except:
            return HttpResponseNotFound(HttpResponse('ERROR 404: No tienes ningún dispositivo añadido con ese id'))
        
        if device_to_detect.user.id != request.user.id:
            return HttpResponseForbidden(HttpResponse('ERROR 403: No puedes detectar dispositivos de otros usuarios'))


        # Detección de dispositivo simple empieza
        if device_to_detect.format == 'Dirección IP' or device_to_detect.format == 'Dirección URL':
            res = single_device_detection(device_to_detect, request.user, request.POST.get("own_dicc", None)=="own_dicc_true")

            if 'No open ports' in res:
                detection = Detection(device=device_to_detect, device_type=res['Device type'], open_ports=res['No open ports'])
                
            else:
                detection = Detection(device=device_to_detect, device_type=res['Device type'], open_ports=res['Open ports'])

            if 'Whatweb' in res:
                whatweb = res['Whatweb']
                whatweb = whatweb.replace('%', '').split('\n')
                whatweb = list(set(', '.join(whatweb).split(', ')[:-1]))
                http_info = whatweb
            
            detection.save()
            messages.success(request, 'El dispositivo {} se ha detectado correctamente'.format(device_to_detect.name))
            device_to_detect.detected = True
            device_to_detect.save()

            create_table_html([device_to_detect.name, detection.open_ports, detection.device_type, http_info], detection)
            return redirect(list_devices)
        # Detección de dispositivo simple acaba


        # Detección de dispositivo rango empieza
        else:
            res = range_device_detection(device_to_detect, request.user, request.POST.get("own_dicc", None)=="own_dicc_true")
            detection = Detection.objects.create(device=device_to_detect, device_type='Rango', open_ports='N/A')
            detection.save()
            messages.success(request, 'El dispositivo {} se ha detectado correctamente'.format(device_to_detect.name))
            device_to_detect.detected = True
            device_to_detect.save()

            create_table_html_for_range(res, device_to_detect.name, detection)
            return redirect(list_devices)
        # Detección de dispositivo rango acaba

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
    
    own_dicc_exists = False
    if os.path.exists('detection/diccs/' + str(request.user.username)+ str(request.user.id)): own_dicc_exists = True
    return render(request, 'training.html', {'own_dicc_exists': own_dicc_exists, 'form': TrainingForm()})


def training_with_file(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    
    if request.method == 'POST' and request.FILES['training_file']:
        if os.path.splitext(str(request.FILES['training_file']))[1] != '.json':
            messages.error(request, """Extensión de archivo no permitida, recuerda que solo se pueden subir archivos con extensión .json""")
            return redirect(training)
            
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
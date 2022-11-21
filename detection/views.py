from django.shortcuts import render, redirect
from django.http import FileResponse, Http404
from django.http.response import HttpResponse, HttpResponseForbidden, HttpResponseNotFound
from .utils import single_device_detection, create_table_html, create_table_html_for_range, range_device_detection, train_devices
from .models import Device, Detection
from authentication.views import *
from devices.views import checkFormats, list_devices
from django.contrib import messages
import os, pdfkit
from adminpanel.views import user_details


def list_detections(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    if len(request.GET) == 0 or request.GET['filter'] == 'all_detections': detections = Detection.objects.filter(device__user__id=request.user.id)
    elif request.GET['filter'] == 'ip_detections': detections = Detection.objects.filter(device__user__id=request.user.id, device__format='Dirección IP')
    elif request.GET['filter'] == 'url_detections': detections = Detection.objects.filter(device__user__id=request.user.id, device__format='Dirección URL')
    elif request.GET['filter'] == 'range_detections': detections = Detection.objects.filter(device__user__id=request.user.id, device__format='Rango de red')
    elif request.GET['filter'] == 'open_ports_detections': detections = Detection.objects.filter(device__user__id=request.user.id).exclude(open_ports='No se han detectado puertos abiertos')
    elif request.GET['filter'] == 'no_open_ports_detections': detections = Detection.objects.filter(device__user__id=request.user.id, open_ports='No se han detectado puertos abiertos')
    
    filter = False
    if len(request.GET) > 0 and len(detections) == 0: filter = True
    return render(request, 'list_detections.html', {'detections': detections, 'filter': filter})


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
    if request.user.is_staff and request.user.id != device.user.id:
        return redirect(user_details, device.user.id)
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
            detection = Detection.objects.create(device=device_to_detect, device_type='Rango de red', open_ports='N/A')
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
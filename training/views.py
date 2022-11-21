from django.shortcuts import render, redirect
from django.http import FileResponse, Http404
from django.http.response import HttpResponse, HttpResponseForbidden, HttpResponseNotFound
from detection.utils import train_devices
from devices.views import checkFormats
from django.contrib import messages
from .forms import TrainingForm
import os, json, shutil

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

            messages.success(request, 'Diccionario de datos entrenado correctamente')
            return redirect(training)
    
        else:
            form = TrainingForm()
    
    own_dicc_exists = False
    if os.path.exists('training/diccs/' + str(request.user.username)+ str(request.user.id)): own_dicc_exists = True
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
        
        messages.success(request, 'Diccionario de datos entrenado correctamente')
        return redirect(training)
    else:
        return redirect(training)

    
def json_example(request):
    json_path = 'training/templates/example.json'
    response = HttpResponse(open(json_path, 'rb'), content_type='application/json')
    response['Content-Disposition'] = "attachment; filename=%s" % 'example.json'
    return response


def see_dicc(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    device_type = [key for key in request.GET][0]
    dicc_path = 'training/diccs/' + str(request.user.username) + str(request.user.id) + '/' + device_type + 'dicc.txt'
    return FileResponse(open(dicc_path, 'rb'), content_type='text/plain')


def remove_diccs(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    dicc_path = 'training/diccs/' + str(request.user.username) + str(request.user.id)
    if not os.path.exists(dicc_path):
        messages.error(request, 'No tienes ningún diccionario de datos añadido, completa el formulario situado en esta página para crear uno')
        return redirect(training)
    shutil.rmtree(dicc_path)
    messages.success(request, 'Diccionario de datos eliminado correctamente')
    return redirect(training)
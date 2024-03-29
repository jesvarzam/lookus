from django.shortcuts import render, redirect
from detection.utils import checkRangeFormat, checkSingleFormat, get_single_format
from detection.models import Device
from adminpanel.views import devices as devices_admin, user_details
from authentication.views import *
from django.contrib.auth.models import User
from django.contrib import messages
import os

def checkFormats(devices):
    for d in devices:
            device_name = d.strip()
            if not checkRangeFormat(device_name) and not checkSingleFormat(device_name):
                return False
    return True


def add(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    if request.method == 'POST':
        devices = request.POST["device_name"].split(',')

        if not checkFormats(devices):
            messages.error(request, 'El formato del dispositivo o de alguno de los dispositivos no es correcto, debe ser una dirección IP o una URL')
            return render(request, 'add.html')
        
        for d in devices:
            device_name = d.strip()

            if len(Device.objects.filter(name=device_name, user=User.objects.get(id=request.user.id))) > 0:
                continue

            if checkRangeFormat(device_name):
                d = Device(name=device_name, format='Rango de red', user=User.objects.get(id=request.user.id))

            elif checkSingleFormat(device_name):
                d = Device(name=device_name, format=get_single_format(device_name), user=User.objects.get(id=request.user.id))
            d.save()

        messages.success(request, 'Dispositivo(s) añadido(s) correctamente')
        return redirect(list_devices)
    return render(request, 'add.html')


def add_with_file(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    if request.method == 'POST' and request.FILES['devices_file']:
        if os.path.splitext(str(request.FILES['devices_file']))[1] != '.txt':
            messages.error(request, """Extensión de archivo no permitida, recuerda que solo se pueden subir archivos con extensión .txt""")
            return redirect(add)
        devices = request.FILES['devices_file'].read().decode().split(',')
        if not checkFormats(devices):
            messages.error(request, """El archivo contiene algún dispositivo en formato incorrecto. 
            Por favor, comprueba que el formato de todos los dispositivos es correcto y vuelve a intentarlo.""")
            return redirect(add)
        
        for dev in devices:

            dev = dev.strip()

            if len(Device.objects.filter(name=dev, user=User.objects.get(id=request.user.id))) > 0:
                continue

            format = get_single_format(dev)

            if checkRangeFormat(dev):
                format = 'Rango de red'

            user = User.objects.get(id=request.user.id)
            
            d = Device.objects.create(name=dev, format=format, user=user)
            d.save()
        
        messages.success(request, 'Dispositivo(s) guardado(s) correctamente')
        return redirect(list_devices)
    else:
        return redirect(add)


def list_devices(request):
    if not request.user.is_authenticated: return redirect(sign_in)
    if len(request.GET) == 0 or request.GET['filter'] == 'all_devices': devices = Device.objects.filter(user=User.objects.get(id=request.user.id))
    elif request.GET['filter'] == 'ip_devices': devices = Device.objects.filter(format='Dirección IP', user=User.objects.get(id=request.user.id))
    elif request.GET['filter'] == 'url_devices': devices = Device.objects.filter(format='Dirección URL', user=User.objects.get(id=request.user.id))
    elif request.GET['filter'] == 'range_devices': devices = Device.objects.filter(format='Rango de red', user=User.objects.get(id=request.user.id))
    elif request.GET['filter'] == 'detected_devices': devices = Device.objects.filter(detected=True, user=User.objects.get(id=request.user.id))
    elif request.GET['filter'] == 'undetected_devices': devices = Device.objects.filter(detected=False, user=User.objects.get(id=request.user.id))

    filter = False
    if len(request.GET) > 0 and len(devices) == 0: filter = True
    own_dicc_exists = False
    if os.path.exists('training/diccs/' + str(request.user.username) + str(request.user.id)): own_dicc_exists = True
    return render(request, 'list_devices.html', {'devices': devices, 'own_dicc_exists': own_dicc_exists, 'filter': filter})


def remove(request, device_id):
    if not request.user.is_authenticated: return redirect(sign_in)

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

    if request.user.is_staff and request.user.id != device.user.id:
        return redirect(user_details, device.user.id)
    return redirect(list_devices)


def remove_all(request):
    if not request.user.is_authenticated: return redirect(sign_in)

    devices = Device.objects.filter(user__id=request.user.id)

    for device in devices:
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
    return redirect(list_devices)
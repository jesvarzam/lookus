from django.shortcuts import render, redirect
from detection.utils import checkRangeFormat
from detection.models import Device
from .forms import DetectionForm
from authentication.views import *
from django.contrib.auth.models import User
from django.contrib import messages
import os


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
            return redirect(list_devices)
        
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
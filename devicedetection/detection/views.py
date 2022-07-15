from django.shortcuts import render, redirect
from .forms import DetectionForm
from .models import Device
from authentication.views import *

def add(request):
    if request.method == 'POST':
        form = DetectionForm(request.POST)
        if form.is_valid():
            d = Device(name=form.cleaned_data['device_name'])
            d.save()
            return redirect(index)
    
    else:
        form = DetectionForm()
    return render(request, 'add.html', {'form': form, 'STATIC_URL':settings.STATIC_URL})

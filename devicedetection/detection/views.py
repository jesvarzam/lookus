from django.shortcuts import render, redirect
from .forms import DetectionForm
from .models import Device
from authentication.views import *
from django.contrib.auth.models import User

def add(request):
    if request.method == 'POST':
        form = DetectionForm(request.POST)
        if form.is_valid():

            d = Device(name=form.cleaned_data['name'], user=User.objects.get(id=request.user.id))
            d.save()
            return redirect(index)
        
        else:
            return render(request, 'add.html', {'form': form})
    
    else:
        form = DetectionForm()
    return render(request, 'add.html', {'form': form})

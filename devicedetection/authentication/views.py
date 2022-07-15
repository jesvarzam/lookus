from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth import login, authenticate, logout
from devicedetection import settings

def index(request):
    return render(request, 'index.html', {'STATIC_URL':settings.STATIC_URL})


def sign_in(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username=form.cleaned_data.get('username')
            password=form.cleaned_data.get('password')
            user=authenticate(request, username=username,password=password)
            
            if user is not None:
                login(request, user)
                
                return redirect(index)
    
    else:
        form=AuthenticationForm()
    return render(request, 'signin.html', {'form': form, 'STATIC_URL':settings.STATIC_URL})


def sign_up(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect(index)
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})


def log_out(request):
    logout(request)
    return redirect(index)
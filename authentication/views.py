from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
import re

def index(request):
    if request.user.is_authenticated:
        return render(request, 'index.html')
    return redirect(sign_in)


def validate(username, password, confirmed_password, first_name, last_name):
    if len(first_name) > 20:
        return 'El nombre debe ser menor a 20 caracteres'
    if len(last_name) > 20:
        return 'Los apellidos deben ser menores a 20 caracteres'
    if len(username) > 20:
        return 'El usuario debe ser menor a 20 caracteres'
    elif User.objects.filter(username=username).exists():
        return 'Ya existe un usuario con ese nombre'
    elif not re.search(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$", password):
        return 'La contraseña debe tener un mínimo 8 caracteres, y al menos una letra y un número'
    elif confirmed_password != password:
        return 'Las contraseñas deben ser iguales'
    return ''


def sign_in(request):
    if request.user.is_authenticated: return redirect(index)
    if request.method == "POST":
        username=request.POST['username']
        password=request.POST['password']
        user=authenticate(request, username=username,password=password)
        if user is None:
            messages.error(request, 'Usuario o contraseña incorrectos')
            return render(request, 'signin.html')
        login(request, user)
        return redirect(index)
    return render(request, 'signin.html')


def sign_up(request):
    if request.user.is_authenticated: return redirect(index)
    if request.method == "POST":
        username=request.POST['username']
        password=request.POST['password1']
        confirmed_password=request.POST['password2']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        validation = validate(username, password, confirmed_password, first_name, last_name)
        if validation == '':
            user = User.objects.create_user(username=username, password=password)
            user.first_name = first_name
            user.last_name = last_name
            user.save()
            user = authenticate(username=username, password=password)
            login(request, user)
            return redirect(index)
        else:
            messages.error(request, validation)
            return render(request, 'signup.html')
    return render(request, 'signup.html')


def log_out(request):
    if not request.user.is_authenticated: return redirect(index)
    logout(request)
    return redirect(index)
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
import re

def index(request):
    if request.user.is_authenticated:
        return render(request, 'index.html')
    return redirect(sign_in)


def validate(first_name, last_name, username, password, confirmed_password):
    if len(first_name) > 20:
        return 'El nombre debe ser menor a 20 caracteres'
    if len(last_name) > 20:
        return 'Los apellidos deben ser menores a 20 caracteres'
    if username == '':
        return 'Introduce un usuario'
    if len(username) > 20:
        return 'El usuario debe ser menor a 20 caracteres'
    elif User.objects.filter(username=username).exists():
        return 'Ya existe un usuario con ese nombre'
    elif not re.search(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$", password):
        return 'La contraseña debe tener un mínimo 8 caracteres, y al menos una letra y un número'
    elif confirmed_password != password:
        return 'Las contraseñas deben ser iguales'
    return ''


def validate_profile(name, surname):
    if len(name) > 20:
        return 'El nombre debe ser menor a 20 caracteres'
    if len(surname) > 20:
        return 'Los apellidos deben ser menores a 20 caracteres'
    return ''

def validate_passwords(new_password, confirmed_new_password):
    if not re.search(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$", new_password):
        return 'La nueva contraseña debe tener un mínimo 8 caracteres, y al menos una letra y un número'
    elif confirmed_new_password != new_password:
        return 'Las nuevas contraseñas deben ser iguales'
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
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username=request.POST['username']
        password=request.POST['password1']
        confirmed_password=request.POST['password2']
        validation = validate(first_name, last_name, username, password, confirmed_password)
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


def profile(request):
    if request.user.is_authenticated:
        return render(request, 'profile.html')
    return redirect(sign_in)


def update_profile(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            name = request.POST['name']
            surname = request.POST['surname']
            validation = validate_profile(name, surname)
            if validation == '':
                user = User.objects.get(id=request.user.id)
                user.first_name = name
                user.last_name = surname
                user.save()
                messages.success(request, 'Perfil actualizado correctamente')
            else:
                messages.error(request, validation)
            return render(request, 'profile.html')
    return redirect(sign_in)


def update_password(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            new_password = request.POST['new_password1']
            confirmed_new_password = request.POST['new_password2']
            validation = validate_passwords(new_password, confirmed_new_password)
            if validation == '':
                user = User.objects.get(id=request.user.id)
                user.set_password(new_password)
                user.save()
                login(request, user)
                messages.success(request, 'Contraseña cambiada correctamente')
            else:
                messages.error(request, validation)
            return render(request, 'profile.html')
    return redirect(sign_in)

def log_out(request):
    if not request.user.is_authenticated: return redirect(index)
    logout(request)
    return redirect(index)
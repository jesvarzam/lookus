from django import forms

class TrainingForm(forms.Form):

    web_servers = forms.CharField(label='Páginas web', max_length=200, required=False)
    routers = forms.CharField(label='Routers', max_length=200, required=False)
    printers = forms.CharField(label='Impresoras', max_length=200, required=False)
    cameras = forms.CharField(label='Cámaras', max_length=200, required=False)
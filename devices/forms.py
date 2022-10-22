from django import forms
from .models import Device
from detection.utils import checkSingleFormat, checkRangeFormat

class DetectionForm(forms.ModelForm):

    class Meta:

        model = Device
        fields = ['name']

    def clean(self):

        super(DetectionForm, self).clean()

        device_name = self.cleaned_data['name']

        if not checkSingleFormat(device_name) and not checkRangeFormat(device_name):
            self.errors['name'] = self.error_class(['Invalid format for this device'])

        return self.cleaned_data


class TrainingForm(forms.Form):

    web_servers = forms.CharField(label='Páginas web', max_length=200)
    routers = forms.CharField(label='Routers', max_length=200)
    printers = forms.CharField(label='Impresoras', max_length=200)
    cameras = forms.CharField(label='Cámaras', max_length=200)
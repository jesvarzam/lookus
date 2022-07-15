from django import forms
from .models import Device
from .utils import *

class DetectionForm(forms.ModelForm):

    class Meta:

        model = Device
        fields = ['name']

    def clean(self):

        super(DetectionForm, self).clean()

        device_name = self.cleaned_data['name']

        if not checkSingleFormat(device_name):
            self.errors['name'] = self.error_class(['Invalid format for this device'])

        return self.cleaned_data
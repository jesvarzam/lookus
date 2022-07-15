from django import forms

class DetectionForm(forms.Form):

    device_name = forms.CharField(max_length=50, min_length=1, required=True)
from django import forms

class EmailForm(forms.Form):

    email = forms.CharField(max_length=100, required=True)
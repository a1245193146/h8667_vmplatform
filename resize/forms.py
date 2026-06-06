from django import forms
from .models import DiskResizeTask


class DiskResizeForm(forms.ModelForm):

    class Meta:
        model = DiskResizeTask

        fields = [
            'vm_ip',
            'disk_key',
            'disk_label',
            'current_size',
            'add_size',
            'reason',
        ]

        widgets = {
            'vm_ip': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '例如: 192.168.1.100',
                'id': 'id_vm_ip',
            }),

            'disk_key': forms.HiddenInput(),

            'disk_label': forms.HiddenInput(),

            'current_size': forms.HiddenInput(),

            'add_size': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': '扩容大小 (GB)',
                'min': 1,
                'max': 500,
            }),

            'reason': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': '请说明扩容原因',
            }),
        }

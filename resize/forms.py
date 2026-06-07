from django import forms
from .models import DiskResizeTask, DomainTask


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


class DomainForm(forms.ModelForm):

    class Meta:
        model = DomainTask
        fields = ['domain', 'backend_ip', 'port', 'reason']
        widgets = {
            'domain': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '例如: myapp.4307.com',
                'id': 'id_domain',
            }),
            'backend_ip': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '例如: 192.168.1.100',
                'id': 'id_backend_ip',
            }),
            'port': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': '后端服务端口 (1-65535)',
                'min': 1,
                'max': 65535,
                'id': 'id_port',
            }),
            'reason': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': '请说明申请原因',
                'id': 'id_reason',
            }),
        }

    def clean_domain(self):
        domain = self.cleaned_data.get('domain', '').strip()
        if not domain.endswith('.4307.com'):
            raise forms.ValidationError('域名必须以 .4307.com 结尾，例如: myapp.4307.com')
        return domain

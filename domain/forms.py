from django import forms

from .models import DomainTask


class DomainTaskForm(forms.ModelForm):
    class Meta:
        model = DomainTask
        fields = ['domain', 'target_ip', 'target_port', 'reason']
        widgets = {
            'domain': forms.TextInput(attrs={'class': 'form-control', 'placeholder': '例如: myapp.4307.com'}),
            'target_ip': forms.TextInput(attrs={'class': 'form-control', 'placeholder': '例如: 192.168.1.100'}),
            'target_port': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': '例如: 8080', 'min': 1, 'max': 65535}),
            'reason': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': '请填写申请原因'}),
        }

    def clean_domain(self):
        domain = self.cleaned_data['domain']
        if '4307' not in domain:
            raise forms.ValidationError('域名必须包含 4307.com 后缀')
        return domain

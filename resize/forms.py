from django import forms
from .models import DiskResizeTask, DomainTask, ServerAuthTask, TrustSiteTask


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


class ServerAuthForm(forms.ModelForm):

    class Meta:
        model = ServerAuthTask
        fields = ['login_account', 'hostname_ip', 'reason']
        widgets = {
            'login_account': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '例如: huangjunkang',
                'id': 'id_login_account',
            }),
            'hostname_ip': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '例如: 192.168.2.73,192.168.2.74',
                'id': 'id_hostname_ip',
            }),
            'reason': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': '请说明授权原因',
                'id': 'id_reason',
            }),
        }

    def clean_login_account(self):
        account = self.cleaned_data.get('login_account', '').strip()
        if not account:
            raise forms.ValidationError('授权域账号不能为空')
        return account

    def clean_hostname_ip(self):
        value = self.cleaned_data.get('hostname_ip', '').strip()
        if not value:
            raise forms.ValidationError('服务器IP/主机名不能为空')
        # 规范化: 去掉每段两端空白和空项
        parts = [p.strip() for p in value.split(',') if p.strip()]
        if not parts:
            raise forms.ValidationError('请输入至少一个有效的服务器IP/主机名')
        return ','.join(parts)


class TrustSiteForm(forms.ModelForm):

    class Meta:
        model = TrustSiteTask
        fields = ['domain', 'reason']
        widgets = {
            'domain': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '例如: myapp.4307.com',
                'id': 'id_domain',
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
        if not domain or '.' not in domain:
            raise forms.ValidationError('无效的域名格式')
        return domain

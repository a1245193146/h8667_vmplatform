from django import forms
from .models import (
    ChangeRecord, DiskResizeTask, DomainTask, ServerAuthTask, TrustSiteTask,
)
from .services.vc_service import MAX_ADD_GB


class DiskResizeForm(forms.ModelForm):

    class Meta:
        model = DiskResizeTask

        fields = [
            'vm_ip',
            'disk_key',
            'disk_label',
            'current_size',
            'add_size',
            'drive_letter',
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

            'drive_letter': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '选填，如 D',
                'maxlength': 1,
                'id': 'id_drive_letter',
            }),

            'reason': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': '请说明扩容原因',
            }),
        }

    def clean_drive_letter(self):
        value = (
            self.cleaned_data.get('drive_letter', '')
            .strip().upper()
        )
        if value:
            if len(value) != 1 or not ('A' <= value <= 'Z'):
                raise forms.ValidationError(
                    '盘符必须是单个字母，如 D'
                )
        return value

    def clean_add_size(self):
        value = self.cleaned_data.get('add_size')
        if value is None:
            return value
        if value < 1 or value > MAX_ADD_GB:
            raise forms.ValidationError(
                f'扩容大小必须在 1-{MAX_ADD_GB} GB 之间'
            )
        return value


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


class ChangeForm(forms.ModelForm):
    """变更登记表单（级别由系统自动判定，审批默认同意）"""

    class Meta:
        model = ChangeRecord
        fields = [
            'serial_no',
            'change_type',
            'server_ip',
            'reason',
            'impact_scope',
            'rollback_plan',
        ]
        widgets = {
            'serial_no': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '例如: BG-2026-001',
                'id': 'id_serial_no',
            }),
            'change_type': forms.Select(attrs={
                'class': 'form-control',
                'id': 'id_change_type',
            }),
            'server_ip': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '例如: 192.168.1.10,192.168.1.11',
                'id': 'id_server_ip',
            }),
            'reason': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': '请说明变更原因',
                'id': 'id_reason',
            }),
            'impact_scope': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': '请说明变更可能影响的业务范围、系统或用户',
                'id': 'id_impact_scope',
            }),
            'rollback_plan': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': '选填，留空将自动填写：恢复快照和配置还原',
                'id': 'id_rollback_plan',
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 回退方案选填（留空由 model save 自动补默认值）
        self.fields['rollback_plan'].required = False

    def clean_server_ip(self):
        value = self.cleaned_data.get('server_ip', '').strip()
        if not value:
            raise forms.ValidationError('操作服务器IP不能为空')
        # 规范化: 逗号分隔，去掉每段两端空白和空项
        parts = [p.strip() for p in value.split(',') if p.strip()]
        if not parts:
            raise forms.ValidationError('请输入至少一个有效的服务器IP')
        return ','.join(parts)

    def clean_rollback_plan(self):
        # 允许留空，model save 时自动补默认回退方案
        return self.cleaned_data.get('rollback_plan', '').strip()

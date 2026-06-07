from typing import Any, cast

from .models import DiskResizeTask, DomainTask
from .sso_utils import get_sso_user, get_sso_username, is_admin


def sso_context(request):
    """为所有模板注入 SSO 用户信息和待审批数量。"""

    sso = get_sso_user(request)

    if not sso:
        return {
            'is_authenticated': False,
            'sso_username': '',
            'is_admin': False,
            'pending_count': 0,
            'domain_pending_count': 0,
        }

    admin = is_admin(request)
    count = 0
    domain_count = 0

    if admin:
        try:
            count = cast(Any, DiskResizeTask).objects.filter(
                approval_status='pending'
            ).count()
        except Exception:
            # 如果数据库连接有问题，返回0
            count = 0

        try:
            domain_count = cast(Any, DomainTask).objects.filter(
                approval_status='pending'
            ).count()
        except Exception:
            domain_count = 0

    return {
        'is_authenticated': True,
        'sso_username': sso.get('user_name', ''),
        'is_admin': admin,
        'pending_count': count,
        'domain_pending_count': domain_count,
    }

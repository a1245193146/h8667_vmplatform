"""运维分析模块权限装饰器。

第一阶段全部为只读分析，无危险操作；但仍要求 SSO 登录，且触发采集/登记维护
限管理员。复用 resize.sso_utils（与 firewall/antivirus 同口径）。
"""
from functools import wraps

from django.http import JsonResponse

from resize.sso_utils import get_sso_user, is_admin


def ops_admin_required(view_func):
    """要求 SSO 登录且具备管理员角色；未登录/非管理员返回 JsonResponse 403。"""

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not get_sso_user(request):
            return JsonResponse({'error': '未登录，请通过 SSO 认证'}, status=403)
        if not is_admin(request):
            return JsonResponse({'error': '无权限，需要管理员角色'}, status=403)
        return view_func(request, *args, **kwargs)

    return wrapper

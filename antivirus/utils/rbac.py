"""病毒模块权限装饰器。

红线：恢复文件 / 最终清理 / 确认恶意 / 标记误报 / 留存隔离文件 → 仅管理员。
复用 resize.sso_utils 的 SSO 会话与管理员判定（与 firewall.utils.rbac 同口径）。
"""
from functools import wraps

from django.http import JsonResponse

from resize.sso_utils import get_sso_user, is_admin


def av_admin_required(view_func):
    """要求 SSO 登录且具备管理员角色；未登录/非管理员返回 JsonResponse 403。"""

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not get_sso_user(request):
            return JsonResponse({'error': '未登录，请通过 SSO 认证'}, status=403)
        if not is_admin(request):
            return JsonResponse({'error': '无权限，需要管理员角色'}, status=403)
        return view_func(request, *args, **kwargs)

    return wrapper

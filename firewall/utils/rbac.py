"""防火墙模块权限装饰器（SPEC-firewall.md §6/§8）。

红线：关防火墙 / 删规则 / 审批策略申请 → 仅管理员。
复用 resize.sso_utils 的 SSO 会话与管理员判定。
"""
from functools import wraps

from django.http import JsonResponse

from resize.sso_utils import get_sso_user, is_admin


def fw_admin_required(view_func):
    """要求 SSO 登录且具备管理员角色。

    未登录 / 非管理员均返回 JsonResponse 403。
    用于 fw_host_firewall(disable)、fw_request_review、
    fw_rule_remove、fw_rule_rollback 等高危操作。
    """

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not get_sso_user(request):
            return JsonResponse(
                {'error': '未登录，请通过 SSO 认证'},
                status=403,
            )
        if not is_admin(request):
            return JsonResponse(
                {'error': '无权限，需要管理员角色'},
                status=403,
            )
        return view_func(request, *args, **kwargs)

    return wrapper

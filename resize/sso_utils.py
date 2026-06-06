"""SSO 认证工具函数。

基于 hpjx SSO 中间件注入的 request.SsoUserInfo 字典，
替代 Django 内置的 request.user 认证体系。

SsoUserInfo 结构示例:
{
    'user_name': '黄XX',
    'samaccountname': 'huangbo',
    'roles_name': '兼职信息化管理员,部门_信息化中心,职员',
    ...
}
"""

from functools import wraps

from django.http import JsonResponse
from django.shortcuts import redirect


ADMIN_ROLE = '兼职信息化管理员'


def get_sso_user(request):
    """获取 SSO 用户信息字典，未登录返回 None。"""
    return getattr(request, 'SsoUserInfo', None)


def get_sso_username(request):
    """获取当前 SSO 用户名（中文姓名）。"""
    sso = get_sso_user(request)
    if sso:
        return sso.get('user_name', '')
    return ''


def is_admin(request):
    """判断当前用户是否为管理员（角色包含'兼职信息化管理员'）。"""
    sso = get_sso_user(request)
    if not sso:
        return False
    roles = sso.get('roles_name', '')
    return ADMIN_ROLE in roles


def sso_required(view_func):
    """替代 @login_required，检查 SSO 登录状态。

    SSO 中间件未注入 SsoUserInfo 时返回 403。
    """

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not get_sso_user(request):
            return JsonResponse(
                {'error': '未登录，请通过 SSO 认证'},
                status=403
            )
        return view_func(request, *args, **kwargs)

    return wrapper


def admin_required(view_func):
    """要求管理员角色，非管理员返回 403。"""

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not get_sso_user(request):
            return JsonResponse(
                {'error': '未登录'}, status=403
            )
        if not is_admin(request):
            return JsonResponse(
                {'error': '无权限，需要管理员角色'},
                status=403
            )
        return view_func(request, *args, **kwargs)

    return wrapper

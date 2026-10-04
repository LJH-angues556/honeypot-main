"""自定义视图装饰器。

角色体系(见 app/models.py):
- super_admin 超级管理员:全部权限 + 用户管理 + 系统设置 + 节点管理
- admin 普通管理员:查看数据 + 封禁 IP + 告警规则 + 模拟攻击
- viewer 只读观察员:仅查看,不能做任何修改
"""
from functools import wraps

from flask import abort
from flask_login import current_user


def admin_required(view_func):
    """要求已登录且角色为 admin / super_admin(写操作级权限)。

    与 @login_required 叠加:未登录重定向登录页,已登录但权限不足返回 403。
    """

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped


def super_admin_required(view_func):
    """要求已登录且角色为 super_admin(用户管理、系统设置等)。"""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if (not current_user.is_authenticated
                or not current_user.is_super_admin):
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped

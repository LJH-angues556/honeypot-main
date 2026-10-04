"""操作审计日志辅助。

在关键操作处调用 audit(action, detail) 写入 audit_logs 表,
记录当前用户、来源 IP、User-Agent。所有异常只记日志,绝不阻断业务。
"""
import logging

from flask import request
from flask_login import current_user

from .extensions import db
from .models import AuditLog

log = logging.getLogger('honeypot.audit')


def audit(action, detail=''):
    """写入一条审计日志。无 app 上下文或异常时静默跳过。"""
    try:
        user_id = None
        username = None
        try:
            if current_user.is_authenticated:
                user_id = current_user.id
                username = current_user.username
        except Exception:
            pass
        ip = request.remote_addr if request else None
        ua = request.headers.get('User-Agent') if request else None
        entry = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            detail=str(detail)[:2000] if detail else None,
            ip_address=ip,
            user_agent=(ua or '')[:255] or None,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        log.exception('写入审计日志失败 action=%s', action)

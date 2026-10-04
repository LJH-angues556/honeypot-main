"""邮件发送封装

设计要点:
- SMTP 参数:系统设置(system_settings 表)优先,环境变量/Config 兜底
- 发送失败只记日志不抛异常,绝不影响攻击捕获等主流程
- 邮件模板在 templates/email/ 下,使用内联样式(邮件客户端不支持外链 CSS)
- 供 Web 请求、RQ 任务、CLI 脚本调用,调用方需处于 app context 中
"""
import re
from datetime import datetime, timedelta

from flask import current_app, render_template
from flask_mail import Message

from .extensions import db, mail
from .models import User, AttackEvent, AttackerProfile, SystemSetting
from .settings_store import _cast


HIGH_SEVERITIES = ('high', 'critical')


def _explicit_setting(key):
    """返回 (是否在系统设置表中显式配置, 值)。空串视为未配置。"""
    row = db.session.get(SystemSetting, key)
    if row is None or row.value in (None, ''):
        return False, None
    return True, _cast(key, row.value)


def smtp_enabled() -> bool:
    configured, value = _explicit_setting('smtp_enabled')
    if configured:
        return bool(value)
    return current_app.config.get('SMTP_ENABLED', False)


def _apply_smtp_overrides():
    """发送前把系统设置中的 SMTP 参数覆盖到 app.config(Flask-Mail 发送时读取)。"""
    app = current_app._get_current_object()
    mapping = {
        'smtp_host': 'MAIL_SERVER',
        'smtp_port': 'MAIL_PORT',
        'smtp_username': 'MAIL_USERNAME',
        'smtp_password': 'MAIL_PASSWORD',
        'smtp_sender': 'MAIL_DEFAULT_SENDER',
        'smtp_use_tls': 'MAIL_USE_TLS',
    }
    for setting_key, config_key in mapping.items():
        configured, value = _explicit_setting(setting_key)
        if configured:
            app.config[config_key] = value


def _strip_html(html: str) -> str:
    text = re.sub(r'<br\s*/?>', '\n', html or '', flags=re.I)
    text = re.sub(r'<[^>]+>', '', text)
    return re.sub(r'\n{3,}', '\n\n', text).strip()


def send_email(to, subject, html, text=None, attachments=None):
    """发送邮件。成功返回 True;未启用或失败返回 False(不抛异常)。

    attachments: list of (filename, bytes, mimetype) 附件。
    """
    try:
        if not smtp_enabled():
            current_app.logger.info('SMTP 未启用,跳过邮件: %s', subject)
            return False
        _apply_smtp_overrides()
        recipients = [to] if isinstance(to, str) else list(to)
        msg = Message(subject, recipients=recipients)
        msg.html = html
        msg.body = text or _strip_html(html)
        if attachments:
            for filename, data, mimetype in attachments:
                msg.attach(filename, mimetype, data)
        mail.send(msg)
        current_app.logger.info('邮件已发送至 %s: %s', recipients, subject)
        return True
    except Exception as e:
        current_app.logger.exception('邮件发送失败: %s', e)
        return False


def send_test_email(to: str) -> bool:
    """系统设置页的测试邮件。"""
    html = render_template('email/test.html', sent_at=datetime.utcnow())
    return send_email(to, '蜜罐系统测试邮件', html)


def _report_recipients():
    """开启了邮件通知、且有邮箱的管理员。"""
    return [
        u.email for u in User.query
        .filter(User.role.in_(['admin', 'super_admin']),
                User.email_notifications.is_(True),
                User.email.isnot(None)).all()
    ]


def build_daily_stats(day=None):
    """统计指定日期(默认昨天)的攻击数据。"""
    day = day or (datetime.utcnow().date() - timedelta(days=1))
    events_count = AttackEvent.query.filter(
        db.func.date(AttackEvent.timestamp) == day
    ).count()
    new_attackers = AttackerProfile.query.filter(
        db.func.date(AttackerProfile.first_seen) == day
    ).count()
    top_ips = [
        (ip, int(cnt)) for ip, cnt in db.session.query(
            AttackEvent.ip_address, db.func.count(AttackEvent.id))
        .filter(db.func.date(AttackEvent.timestamp) == day)
        .group_by(AttackEvent.ip_address)
        .order_by(db.desc(db.func.count(AttackEvent.id)))
        .limit(10).all()
    ]
    return {'day': day, 'events': events_count,
            'new_attackers': new_attackers, 'top_ips': top_ips}


def send_daily_report(day=None):
    """生成并发送每日报告。返回发送数量。"""
    stats = build_daily_stats(day)
    recipients = _report_recipients()
    if not recipients:
        current_app.logger.info('每日报告跳过:没有开启邮件通知的管理员')
        return 0
    html = render_template('email/daily_report.html', **stats)
    subject = f"【蜜罐日报】{stats['day']} 攻击 {stats['events']} 起"
    ok = send_email(recipients, subject, html)
    return len(recipients) if ok else 0


def send_attack_alert(event):
    """高危攻击实时告警(仅 high/critical)。返回是否发送。"""
    if (event.severity or '').lower() not in HIGH_SEVERITIES:
        return False
    configured, enabled = _explicit_setting('email_alerts_enabled')
    alerts_on = enabled if configured else False
    if not alerts_on:
        return False
    recipients = _report_recipients()
    if not recipients:
        return False
    html = render_template('email/alert.html', event=event)
    subject = f"【蜜罐告警】{event.severity.upper()} 攻击来自 {event.ip_address}"
    return send_email(recipients, subject, html)


def send_alert(rule, event, detail):
    """告警规则触发的通知邮件。与高危告警共用开关与收件人。"""
    configured, enabled = _explicit_setting('email_alerts_enabled')
    alerts_on = enabled if configured else False
    if not alerts_on:
        return False
    recipients = _report_recipients()
    if not recipients:
        return False
    html = render_template('email/rule_alert.html', rule=rule, event=event, detail=detail)
    subject = f"【蜜罐告警】规则「{rule.name}」触发 - {event.ip_address}"
    return send_email(recipients, subject, html)

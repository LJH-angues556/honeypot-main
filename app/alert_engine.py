"""告警规则引擎。

每次攻击事件入库后异步调用 evaluate_alert_rules(event_id),遍历所有启用的规则,
满足条件且未在冷却期内时写入 AlertHistory 并发送告警邮件。

支持的规则类型:
  high_severity  事件严重级别 >= 规则指定级别(或匹配特定 signature)
  ip_frequency   某 IP 在 window_minutes 内事件数 >= threshold
  new_attacker   该攻击者画像为首次出现(仅有当前这一条事件)
  new_country    该 IP 所属国家此前从未出现过(需 GeoIP 已补全)
"""
import logging
from datetime import datetime, timedelta

from app import email_utils
from app.extensions import db
from app.models import AlertHistory, AlertRule, AttackEvent, AttackerProfile

log = logging.getLogger('honeypot.alert')

SEVERITY_ORDER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def _severity_ge(a, b):
    return SEVERITY_ORDER.get(a or 'low', 1) >= SEVERITY_ORDER.get(b or 'low', 1)


def _in_cooldown(rule, ip_address):
    """同一规则同一 IP 在 cooldown_minutes 内已告警过则返回 True。"""
    if not rule.cooldown_minutes:
        return False
    since = datetime.utcnow() - timedelta(minutes=rule.cooldown_minutes)
    return db.session.query(AlertHistory.id).filter(
        AlertHistory.rule_id == rule.id,
        AlertHistory.ip_address == ip_address,
        AlertHistory.created_at >= since,
    ).first() is not None


def _record(rule, event, detail):
    history = AlertHistory(
        rule_id=rule.id,
        profile_id=event.attacker_id,
        event_id=event.id,
        ip_address=event.ip_address,
        detail=detail,
    )
    db.session.add(history)
    db.session.commit()
    log.info('告警触发 rule=%s ip=%s detail=%s', rule.name, event.ip_address, detail)
    # 告警邮件(SMTP 未配置时 send_attack_alert 内部只记日志)
    try:
        email_utils.send_alert(rule, event, detail)
    except Exception:
        log.exception('告警邮件发送失败 rule=%s', rule.name)


def _check_high_severity(rule, event):
    if rule.severity and not _severity_ge(event.severity, rule.severity):
        return None
    if rule.signature and event.signature != rule.signature:
        return None
    sig = event.signature or '(无签名)'
    return f'检测到 {event.severity} 级别攻击: {sig} (服务 {event.honeypot_service})'


def _check_ip_frequency(rule, event):
    threshold = rule.threshold or 0
    window = rule.window_minutes or 1
    since = event.timestamp - timedelta(minutes=window)
    count = db.session.query(AttackEvent.id).filter(
        AttackEvent.ip_address == event.ip_address,
        AttackEvent.timestamp >= since,
    ).count()
    if count >= threshold:
        return f'IP {event.ip_address} 在 {window} 分钟内触发 {count} 次攻击(阈值 {threshold})'
    return None


def _check_new_attacker(rule, event):
    if not event.attacker_id:
        return None
    count = db.session.query(AttackEvent.id).filter(
        AttackEvent.attacker_id == event.attacker_id,
    ).count()
    if count <= 1:
        return f'新攻击者出现: {event.ip_address}'
    return None


def _check_new_country(rule, event):
    profile = event.attacker
    if not profile or not profile.country:
        return None
    same_country = db.session.query(AttackerProfile.id).filter(
        AttackerProfile.country == profile.country,
    ).count()
    if same_country <= 1:
        return f'来自新国家/地区的攻击: {profile.country} ({event.ip_address})'
    return None


CHECKERS = {
    'high_severity': _check_high_severity,
    'ip_frequency': _check_ip_frequency,
    'new_attacker': _check_new_attacker,
    'new_country': _check_new_country,
}


def evaluate_alert_rules(event_id):
    """事件入库后调用:评估所有启用规则,触发告警。异常不影响主流程。"""
    event = db.session.get(AttackEvent, event_id)
    if event is None:
        log.warning('evaluate_alert_rules: 事件不存在 event_id=%s', event_id)
        return
    rules = AlertRule.query.filter_by(enabled=True).all()
    for rule in rules:
        checker = CHECKERS.get(rule.rule_type)
        if checker is None:
            continue
        try:
            detail = checker(rule, event)
        except Exception:
            log.exception('规则 %s 评估异常', rule.name)
            continue
        if detail and not _in_cooldown(rule, event.ip_address):
            _record(rule, event, detail)

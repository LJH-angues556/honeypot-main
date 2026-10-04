from datetime import datetime, timedelta
from typing import Optional

from flask_login import UserMixin
from sqlalchemy.ext.hybrid import hybrid_property
from werkzeug.security import generate_password_hash, check_password_hash

from .extensions import db

NODE_ONLINE_WINDOW = 300  # 心跳超过 5 分钟视为离线

ROLE_SUPER_ADMIN = 'super_admin'
ROLE_ADMIN = 'admin'
ROLE_VIEWER = 'viewer'
ROLES = (ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_VIEWER)
ROLE_LABELS = {
    ROLE_SUPER_ADMIN: '超级管理员',
    ROLE_ADMIN: '管理员',
    ROLE_VIEWER: '只读观察员',
}
# 可执行写操作(封禁、告警规则、模拟攻击等)的角色
WRITE_ROLES = (ROLE_SUPER_ADMIN, ROLE_ADMIN)


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default=ROLE_VIEWER, nullable=False,
                     server_default=ROLE_VIEWER)
    active = db.Column(db.Boolean, default=True, nullable=False, server_default='1')
    email_notifications = db.Column(db.Boolean, default=True, nullable=False)
    theme_preference = db.Column(db.String(10), default='light', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @hybrid_property
    def is_admin(self) -> bool:
        """管理员或超级管理员视为后台管理角色(写权限)。"""
        return self.role in WRITE_ROLES

    @is_admin.expression
    def is_admin(cls):
        return cls.role.in_(list(WRITE_ROLES))

    @property
    def is_super_admin(self) -> bool:
        return self.role == ROLE_SUPER_ADMIN

    @property
    def role_label(self) -> str:
        return ROLE_LABELS.get(self.role, self.role)

    @property
    def is_active(self) -> bool:
        """Flask-Login 依据此值拒绝被禁用用户登录。"""
        return bool(self.active)


class AttackerProfile(db.Model):
    __tablename__ = 'attacker_profiles'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), index=True, nullable=False)
    user_agent = db.Column(db.String(255))
    asn = db.Column(db.String(32))
    isp = db.Column(db.String(128))
    country = db.Column(db.String(64))
    city = db.Column(db.String(64))
    tags = db.Column(db.JSON, nullable=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # IP 黑名单(任务2.7)
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)
    block_reason = db.Column(db.String(255), nullable=True)
    blocked_at = db.Column(db.DateTime, nullable=True)

    # Relationship
    attacks = db.relationship('AttackEvent', backref='attacker', lazy=True)


class AttackEvent(db.Model):
    __tablename__ = 'attack_events'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(45), index=True, nullable=False)
    method = db.Column(db.String(16))
    path = db.Column(db.String(255))
    headers = db.Column(db.JSON)
    payload = db.Column(db.JSON)
    honeypot_service = db.Column(db.String(64))
    signature = db.Column(db.String(128))
    severity = db.Column(db.String(16))

    attacker_id = db.Column(db.Integer, db.ForeignKey('attacker_profiles.id'))

    # 上报节点(任务2.2);历史数据可为空
    node_id = db.Column(db.Integer, db.ForeignKey('honeypot_nodes.id'), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'ip_address': self.ip_address,
            'method': self.method,
            'path': self.path,
            'headers': self.headers,
            'payload': self.payload,
            'honeypot_service': self.honeypot_service,
            'signature': self.signature,
            'severity': self.severity,
            'attacker_id': self.attacker_id,
            'node_id': self.node_id,
        }


class HoneypotNode(db.Model):
    """蜜罐节点:独立部署的诱饵服务实例,通过 node_key + 心跳接入平台。"""
    __tablename__ = 'honeypot_nodes'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    node_key = db.Column(db.String(64), unique=True, index=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    service_type = db.Column(db.String(32), default='http', nullable=False)
    # online/offline 由心跳刷新;真实在线状态以 is_online(5 分钟心跳窗口)为准
    status = db.Column(db.String(16), default='offline', nullable=False)
    last_heartbeat = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    attacks = db.relationship('AttackEvent', backref='node', lazy=True)

    @property
    def is_online(self) -> bool:
        if not self.last_heartbeat:
            return False
        return (datetime.utcnow() - self.last_heartbeat) <= timedelta(seconds=NODE_ONLINE_WINDOW)

    @property
    def display_status(self) -> str:
        return 'online' if self.is_online else 'offline'


class SystemSetting(db.Model):
    """系统级配置(key-value)。key 见 app/settings_store.py 的 SETTING_SPECS。"""
    __tablename__ = 'system_settings'

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)


class AlertRule(db.Model):
    """告警规则:满足条件时触发告警邮件并写入 AlertHistory。"""
    __tablename__ = 'alert_rules'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    # high_severity / ip_frequency / new_attacker / new_country
    rule_type = db.Column(db.String(32), nullable=False)
    # high_severity 用:目标严重级别(low/medium/high/critical)
    severity = db.Column(db.String(16), nullable=True)
    # high_severity 可选:匹配特定攻击签名(为空表示不限制)
    signature = db.Column(db.String(128), nullable=True)
    # ip_frequency 用:窗口内事件数阈值
    threshold = db.Column(db.Integer, nullable=True)
    # ip_frequency 用:统计窗口(分钟)
    window_minutes = db.Column(db.Integer, nullable=True)
    # 同一规则同一 IP 的告警冷却(分钟),0 表示不冷却
    cooldown_minutes = db.Column(db.Integer, default=60, nullable=False)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    histories = db.relationship('AlertHistory', backref='rule', lazy=True,
                                cascade='all, delete-orphan')


class AlertHistory(db.Model):
    """告警触发历史,用于冷却判断与审计展示。"""
    __tablename__ = 'alert_histories'

    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('alert_rules.id'), nullable=False)
    profile_id = db.Column(db.Integer, db.ForeignKey('attacker_profiles.id'),
                           nullable=True)
    event_id = db.Column(db.Integer, db.ForeignKey('attack_events.id'),
                         nullable=True)
    ip_address = db.Column(db.String(45), index=True, nullable=False)
    detail = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class AuditLog(db.Model):
    """管理员操作审计日志。只读,不可通过界面删除。"""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username = db.Column(db.String(80), nullable=True)
    action = db.Column(db.String(64), nullable=False)
    detail = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ThreatIntelRecord(db.Model):
    """威胁情报记录(任务4.3)。

    两种 kind:
    - 'feed':开源情报源同步的网段/IP 条目(Spamhaus DROP/EDROP),indicator 为 CIDR
    - 'ip':单个攻击者 IP 的查询缓存(命中 feed 或 AbuseIPDB 查询结果),indicator 为 IP
    """
    __tablename__ = 'threat_intel_records'

    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(64), nullable=False, index=True)
    kind = db.Column(db.String(8), nullable=False, default='ip')  # ip / feed
    source = db.Column(db.String(32), nullable=False, default='unknown')
    malicious = db.Column(db.Boolean, nullable=False, default=True)
    category = db.Column(db.String(128), nullable=True)
    confidence = db.Column(db.Integer, nullable=True)  # AbuseIPDB 置信度 0-100
    detail = db.Column(db.String(255), nullable=True)
    checked_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('indicator', 'kind', 'source',
                            name='uq_threat_indicator_kind_source'),
    )



"""第三阶段功能测试:Redis 协议解析/签名检测、告警规则、审计日志、数据导出。"""
import os
import sys
import json
import io

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db as _db
from app.models import User, AttackEvent, AttackerProfile, AlertRule, AlertHistory, AuditLog
from app.alert_engine import evaluate_alert_rules
from app.audit import audit
from app import export_utils


def login(client, username='admin', password='password123'):
    return client.post('/login', data={'username': username, 'password': password})


class TestConfig:
    TESTING = True
    SECRET_KEY = 'test-secret'
    API_SECRET_KEY = 'test-api-secret'
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_HOST = 'localhost'
    REDIS_PORT = 6379
    REDIS_DB = 0
    REDIS_PASSWORD = None
    REMEMBER_COOKIE_DURATION_DAYS = 7
    REGISTER_ENABLED = False
    GEOIP_ENABLED = False
    THREAT_INTEL_ENABLED = False
    RATELIMIT_ENABLED = False
    RATELIMIT_STORAGE_URI = 'memory://'
    RQ_ENABLED = False


@pytest.fixture()
def app():
    from app.settings_store import clear_cache
    clear_cache()
    app = create_app(TestConfig)
    with app.app_context():
        _db.create_all()
    yield app
    with app.app_context():
        _db.drop_all()
    clear_cache()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_user(app):
    with app.app_context():
        u = User(username='admin', email='admin@test.com', role='super_admin')
        u.set_password('password123')
        _db.session.add(u)
        _db.session.commit()
        return u


class _FakeSock:
    """给 RESPReader 用的假 socket:预设一段字节流,recv 逐步吐出。"""
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def recv(self, n):
        chunk = self.data[self.pos:self.pos + n]
        self.pos += len(chunk)
        return chunk


# ---------------- Redis 蜜罐纯函数测试 ----------------

class TestRedisHoneypot:
    def test_detect_signature_ping(self):
        from honeypots.redis_honeypot import detect_signature
        assert detect_signature('ping') == ('redis_unauthorized', 'low')

    def test_detect_signature_config_set_dir(self):
        from honeypots.redis_honeypot import detect_signature
        sig, sev = detect_signature('CONFIG SET dir /var/spool/cron')
        assert sig == 'redis_exploit_attempt'
        assert sev == 'high'

    def test_detect_signature_slaveof_rce(self):
        from honeypots.redis_honeypot import detect_signature
        sig, sev = detect_signature('SLAVEOF 1.2.3.4 6379')
        assert sig == 'redis_rce_attempt'
        assert sev == 'critical'

    def test_detect_signature_ssh_rsa_high(self):
        from honeypots.redis_honeypot import detect_signature
        sig, sev = detect_signature('SET xxx "\\n\\nssh-rsa AAAAB3Nza...\\n\\n"')
        assert sig == 'redis_exploit_attempt'
        assert sev == 'high'

    def test_resp_reader_simple_array(self):
        from honeypots.redis_honeypot import RESPReader
        reader = RESPReader(_FakeSock(b'*1\r\n$4\r\nping\r\n'))
        assert reader.read_command() == ['ping']

    def test_resp_reader_multi_args(self):
        from honeypots.redis_honeypot import RESPReader
        reader = RESPReader(_FakeSock(b'*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n'))
        assert reader.read_command() == ['CONFIG', 'SET', 'dir']

    def test_resp_reader_inline(self):
        from honeypots.redis_honeypot import RESPReader
        reader = RESPReader(_FakeSock(b'INFO\r\n'))
        assert reader.read_command() == ['INFO']


# ---------------- 告警规则引擎测试 ----------------

class TestAlertEngine:
    def test_high_severity_rule_triggers(self, app):
        with app.app_context():
            rule = AlertRule(name='高危事件告警', rule_type='high_severity',
                             severity='high', enabled=True)
            _db.session.add(rule)
            _db.session.commit()

            p = AttackerProfile(ip_address='5.6.7.8')
            _db.session.add(p)
            _db.session.flush()
            e = AttackEvent(ip_address='5.6.7.8', method='GET', path='/',
                            severity='critical', attacker=p)
            _db.session.add(e)
            _db.session.commit()

            evaluate_alert_rules(e.id)
            hist = AlertHistory.query.filter_by(rule_id=rule.id).first()
            assert hist is not None
            assert hist.event_id == e.id

    def test_high_severity_rule_below_threshold_no_trigger(self, app):
        with app.app_context():
            rule = AlertRule(name='高危事件告警', rule_type='high_severity',
                             severity='high', enabled=True)
            _db.session.add(rule)
            _db.session.commit()

            p = AttackerProfile(ip_address='5.6.7.8')
            _db.session.add(p)
            _db.session.flush()
            e = AttackEvent(ip_address='5.6.7.8', method='GET', path='/',
                            severity='low', attacker=p)
            _db.session.add(e)
            _db.session.commit()

            evaluate_alert_rules(e.id)
            assert AlertHistory.query.filter_by(rule_id=rule.id).count() == 0

    def test_cooldown_prevents_duplicate(self, app):
        with app.app_context():
            rule = AlertRule(name='高危事件告警', rule_type='high_severity',
                             severity='high', cooldown_minutes=10, enabled=True)
            _db.session.add(rule)
            _db.session.commit()

            p = AttackerProfile(ip_address='5.6.7.8')
            _db.session.add(p)
            _db.session.flush()
            e1 = AttackEvent(ip_address='5.6.7.8', method='GET', path='/1',
                             severity='high', attacker=p)
            e2 = AttackEvent(ip_address='5.6.7.8', method='GET', path='/2',
                             severity='high', attacker=p)
            _db.session.add_all([e1, e2])
            _db.session.commit()

            evaluate_alert_rules(e1.id)
            evaluate_alert_rules(e2.id)
            # 冷却期内同一 IP 只触发一次
            assert AlertHistory.query.filter_by(rule_id=rule.id).count() == 1

    def test_disabled_rule_not_evaluated(self, app):
        with app.app_context():
            rule = AlertRule(name='高危事件告警', rule_type='high_severity',
                             severity='high', enabled=False)
            _db.session.add(rule)
            _db.session.commit()

            p = AttackerProfile(ip_address='5.6.7.8')
            _db.session.add(p)
            _db.session.flush()
            e = AttackEvent(ip_address='5.6.7.8', severity='critical', attacker=p)
            _db.session.add(e)
            _db.session.commit()

            evaluate_alert_rules(e.id)
            assert AlertHistory.query.filter_by(rule_id=rule.id).count() == 0


# ---------------- 审计日志测试 ----------------

class TestAuditLog:
    def test_audit_records_entry_via_block_action(self, app, client, admin_user):
        login(client, 'admin')
        with app.app_context():
            p = AttackerProfile(ip_address='9.9.9.9')
            _db.session.add(p)
            _db.session.commit()
            pid = p.id
        # 触发封禁操作(内部调用 audit)
        resp = client.post(f'/admin/attackers/{pid}/block',
                           data={'block_reason': '测试封禁'}, follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            entry = AuditLog.query.filter_by(action='block_ip').first()
            assert entry is not None
            assert entry.username == 'admin'
            assert '9.9.9.9' in (entry.detail or '')

    def test_audit_safe_without_request_context(self, app):
        with app.app_context():
            # 无请求上下文时应静默降级,不抛异常(记录可能带空字段或不写入)
            try:
                audit('no_ctx_action', 'x')
                raised = False
            except Exception:
                raised = True
            assert raised is False


# ---------------- 数据导出测试 ----------------

class TestExport:
    def _make_events(self):
        p = AttackerProfile(ip_address='1.1.1.1')
        _db.session.add(p)
        _db.session.flush()
        e = AttackEvent(ip_address='1.1.1.1', method='GET', path='/admin',
                        honeypot_service='web', signature='sql_injection',
                        severity='high', attacker=p, payload={'q': "' OR 1=1"})
        _db.session.add(e)
        _db.session.commit()
        return [e]

    def test_events_csv_has_bom_and_fields(self, app):
        with app.app_context():
            events = self._make_events()
            csv_text = export_utils.events_csv(events)
            assert csv_text.startswith('﻿')
            assert 'ip_address' in csv_text
            assert '1.1.1.1' in csv_text
            assert 'sql_injection' in csv_text

    def test_events_json_parsable(self, app):
        with app.app_context():
            events = self._make_events()
            data = json.loads(export_utils.events_json(events))
            assert len(data) == 1
            assert data[0]['ip_address'] == '1.1.1.1'
            assert data[0]['severity'] == 'high'

    def test_events_xlsx_bytes(self, app):
        with app.app_context():
            events = self._make_events()
            buf = export_utils.events_xlsx(events)
            assert isinstance(buf, bytes)
            assert buf[:2] == b'PK'  # xlsx 是 zip 格式

    def test_attackers_csv_json_xlsx(self, app):
        with app.app_context():
            p = AttackerProfile(ip_address='2.2.2.2', country='China')
            _db.session.add(p)
            _db.session.commit()
            rows = [(p, 5)]
            csv_text = export_utils.attackers_csv(rows)
            assert csv_text.startswith('﻿')
            assert '2.2.2.2' in csv_text
            assert 'China' in csv_text

            data = json.loads(export_utils.attackers_json(rows))
            assert data[0]['attack_count'] == 5

            buf = export_utils.attackers_xlsx(rows)
            assert buf[:2] == b'PK'

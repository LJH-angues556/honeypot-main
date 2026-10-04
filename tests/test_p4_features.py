"""第四阶段功能测试:SSE 实时推送、用户权限管理。"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db as _db
from app.models import User, AttackEvent, AttackerProfile, ThreatIntelRecord
from app import realtime, threat_intel
from app.settings_store import set_setting


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


def _mk_user(name, role, password='password123'):
    u = User(username=name, email=f'{name}@test.com', role=role)
    u.set_password(password)
    _db.session.add(u)
    _db.session.commit()
    return u


@pytest.fixture()
def users(app):
    with app.app_context():
        su = _mk_user('super1', 'super_admin')
        ad = _mk_user('admin1', 'admin')
        vw = _mk_user('viewer1', 'viewer')
        return su.id, ad.id, vw.id


def login(client, username, password='password123'):
    return client.post('/login', data={'username': username, 'password': password})


# ---------------- SSE 实时推送(4.1) ----------------

class TestSSE:
    def test_stream_requires_login(self, client):
        resp = client.get('/admin/stream', follow_redirects=False)
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_stream_503_when_redis_unavailable(self, client, app, users):
        login(client, 'super1')
        # 测试环境无 Redis,订阅失败应快速 503 而不是挂起
        resp = client.get('/admin/stream')
        assert resp.status_code == 503

    def test_publish_swallows_redis_error(self, app):
        with app.app_context():
            # 无 Redis 时 publish 不抛异常
            realtime.publish_event({'hello': 'world'})

    def test_build_event_payload(self, app):
        with app.app_context():
            p = AttackerProfile(ip_address='3.3.3.3')
            _db.session.add(p)
            _db.session.flush()
            e = AttackEvent(ip_address='3.3.3.3', method='GET', path='/x',
                            severity='high', honeypot_service='web',
                            signature='sql_injection', attacker=p)
            _db.session.add(e)
            _db.session.commit()
            payload = realtime.build_event_payload(e)
            assert payload['id'] == e.id
            assert payload['ip_address'] == '3.3.3.3'
            assert payload['severity'] == 'high'
            assert payload['totals']['total_attacks'] == 1
            assert payload['totals']['unique_attackers'] == 1


# ---------------- 用户权限管理(4.2) ----------------

class TestUserManagement:
    def test_super_admin_can_open_users_page(self, client, app, users):
        login(client, 'super1')
        assert client.get('/admin/users').status_code == 200

    def test_admin_and_viewer_cannot_open_users_page(self, client, app, users):
        login(client, 'admin1')
        assert client.get('/admin/users').status_code == 403
        client.get('/logout')
        login(client, 'viewer1')
        assert client.get('/admin/users').status_code == 403

    def test_super_admin_create_user(self, client, app, users):
        login(client, 'super1')
        resp = client.post('/admin/users/create', data={
            'username': 'newbie', 'email': 'newbie@x.com',
            'password': 'secret123', 'role': 'viewer',
        }, follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            u = User.query.filter_by(username='newbie').first()
            assert u is not None
            assert u.role == 'viewer'
            assert u.check_password('secret123')

    def test_create_user_short_password_rejected(self, client, app, users):
        login(client, 'super1')
        client.post('/admin/users/create', data={
            'username': 'shorty', 'password': '123', 'role': 'viewer'})
        with app.app_context():
            assert User.query.filter_by(username='shorty').first() is None

    def test_change_role(self, client, app, users):
        _, _, vid = users
        login(client, 'super1')
        resp = client.post(f'/admin/users/{vid}/role', data={'role': 'admin'},
                           follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            assert _db.session.get(User, vid).role == 'admin'

    def test_cannot_demote_last_super_admin(self, client, app, users):
        su_id, _, _ = users
        login(client, 'super1')
        client.post(f'/admin/users/{su_id}/role', data={'role': 'admin'})
        with app.app_context():
            assert _db.session.get(User, su_id).role == 'super_admin'

    def test_cannot_disable_self(self, client, app, users):
        su_id, _, _ = users
        login(client, 'super1')
        client.post(f'/admin/users/{su_id}/toggle')
        with app.app_context():
            assert _db.session.get(User, su_id).active is True

    def test_disabled_user_cannot_login(self, client, app, users):
        _, _, vid = users
        login(client, 'super1')
        client.post(f'/admin/users/{vid}/toggle')
        client.get('/logout')
        resp = login(client, 'viewer1')
        # 仍停留在登录页(未跳转到 dashboard)
        assert resp.status_code == 200
        with client.session_transaction() as sess:
            assert '_user_id' not in sess

    def test_reset_password(self, client, app, users):
        _, _, vid = users
        login(client, 'super1')
        client.post(f'/admin/users/{vid}/reset-password',
                    data={'new_password': 'newpass789'})
        client.get('/logout')
        resp = login(client, 'viewer1', 'newpass789')
        assert resp.status_code == 302

    def test_illegal_role_rejected(self, client, app, users):
        _, _, vid = users
        login(client, 'super1')
        client.post(f'/admin/users/{vid}/role', data={'role': 'hacker'})
        with app.app_context():
            assert _db.session.get(User, vid).role == 'viewer'


# ---------------- 角色写权限矩阵 ----------------

class TestRoleWriteMatrix:
    def test_viewer_cannot_block_ip(self, client, app, users):
        with app.app_context():
            p = AttackerProfile(ip_address='7.7.7.7')
            _db.session.add(p)
            _db.session.commit()
            pid = p.id
        login(client, 'viewer1')
        resp = client.post(f'/admin/attackers/{pid}/block',
                           data={'block_reason': 'x'})
        assert resp.status_code == 403
        with app.app_context():
            assert _db.session.get(AttackerProfile, pid).is_blocked is False

    def test_admin_can_block_ip(self, client, app, users):
        with app.app_context():
            p = AttackerProfile(ip_address='8.8.8.8')
            _db.session.add(p)
            _db.session.commit()
            pid = p.id
        login(client, 'admin1')
        resp = client.post(f'/admin/attackers/{pid}/block',
                           data={'block_reason': '扫描'})
        assert resp.status_code == 302
        with app.app_context():
            assert _db.session.get(AttackerProfile, pid).is_blocked is True

    def test_admin_cannot_change_system_settings(self, client, app, users):
        login(client, 'admin1')
        assert client.get('/admin/system-settings').status_code == 403
        assert client.post('/admin/system-settings', data={}).status_code == 403

    def test_super_admin_can_change_system_settings(self, client, app, users):
        login(client, 'super1')
        assert client.get('/admin/system-settings').status_code == 200


# ---------------- 威胁情报(4.3) ----------------

SAMPLE_DROP = """; Spamhaus DROP List 2026/10/04
; do not redistribute without attribution

1.10.16.0/20 ; SBL256894
5.188.10.0/23 ; SBL123456
not-a-cidr ; ignored
"""


class TestThreatIntel:
    def test_parse_feed_text(self):
        entries = threat_intel.parse_feed_text(SAMPLE_DROP)
        assert ('1.10.16.0/20', 'SBL256894') in entries
        assert ('5.188.10.0/23', 'SBL123456') in entries
        assert len(entries) == 2

    def test_lookup_private_ip_returns_none(self, app):
        with app.app_context():
            set_setting('threat_intel_enabled', True)
            assert threat_intel.lookup_ip('192.168.1.1') is None

    def test_disabled_returns_none(self, app):
        with app.app_context():
            set_setting('threat_intel_enabled', False)
            assert threat_intel.lookup_ip('8.8.8.8') is None

    def test_lookup_matches_feed_cidr(self, app, monkeypatch):
        # 不允许任何真实外网调用
        monkeypatch.setattr(threat_intel, '_query_abuseipdb', lambda ip: None)
        with app.app_context():
            set_setting('threat_intel_enabled', True)
            _db.session.add(ThreatIntelRecord(
                indicator='1.10.16.0/20', kind='feed',
                source='spamhaus_drop', malicious=True,
                category='Spamhaus DROP 恶意网段', detail='SBL256894'))
            _db.session.commit()
            threat_intel._feed_cache['expire_at'] = 0  # 清内存缓存

            rec = threat_intel.lookup_ip('1.10.16.5')
            assert rec is not None
            assert rec.malicious is True
            assert rec.source == 'spamhaus_drop'
            assert '命中' in rec.detail

            # 第二次直接走 IP 缓存,不重复匹配
            rec2 = threat_intel.lookup_ip('1.10.16.5')
            assert rec2.id == rec.id

    def test_negative_result_is_cached(self, app, monkeypatch):
        calls = []
        def fake_query(ip):
            calls.append(ip)
            return None
        monkeypatch.setattr(threat_intel, '_query_abuseipdb', fake_query)
        with app.app_context():
            set_setting('threat_intel_enabled', True)
            threat_intel._feed_cache['networks'] = []
            threat_intel._feed_cache['expire_at'] = 9999999999.0
            r1 = threat_intel.lookup_ip('9.9.9.9')
            r2 = threat_intel.lookup_ip('9.9.9.9')
            assert r1.malicious is False
            assert r2.id == r1.id
            # 仅首次查询调用外部源,第二次走缓存
            assert calls == ['9.9.9.9']

    def test_abuseipdb_score_marks_malicious(self, app, monkeypatch):
        monkeypatch.setattr(threat_intel, '_query_abuseipdb',
                            lambda ip: (90, 'AbuseIPDB 威胁评分', 'bad isp'))
        with app.app_context():
            set_setting('threat_intel_enabled', True)
            set_setting('abuseipdb_threshold', 50)
            threat_intel._feed_cache['networks'] = []
            threat_intel._feed_cache['expire_at'] = 9999999999.0
            rec = threat_intel.lookup_ip('77.88.8.8')
            assert rec.malicious is True
            assert rec.confidence == 90
            assert rec.source == 'abuseipdb'

    def test_malicious_attacker_count(self, app):
        with app.app_context():
            _db.session.add(AttackerProfile(ip_address='1.10.16.5'))
            _db.session.add(AttackerProfile(ip_address='8.8.8.8'))
            _db.session.add(ThreatIntelRecord(
                indicator='1.10.16.5', kind='ip', source='spamhaus_drop',
                malicious=True))
            _db.session.add(ThreatIntelRecord(
                indicator='8.8.8.8', kind='ip', source='local_feed',
                malicious=False))
            _db.session.commit()
            assert threat_intel.malicious_attacker_count() == 1

    def test_refresh_feeds_skips_empty_response(self, app, monkeypatch):
        class FakeResp:
            status_code = 200
            text = ''
            def raise_for_status(self):
                pass
        def fake_get(url, timeout):
            return FakeResp()
        monkeypatch.setattr(threat_intel.requests, 'get', fake_get)
        with app.app_context():
            # 空响应不应抛异常,也不应写入数据
            assert threat_intel.refresh_feeds() == 0
            assert ThreatIntelRecord.query.filter_by(kind='feed').count() == 0


# ---------------- 模拟攻击表单增强(4.5) ----------------

class TestSimulateAttackForm:
    def test_custom_params(self, client, app, users):
        login(client, 'admin1')
        resp = client.post('/admin/simulate-attack', data={
            'ip': '55.66.77.88', 'country': 'JP', 'severity': 'high',
            'honeypot_service': 'ssh', 'signature': 'brute_force',
            'user_agent': 'CustomUA/1.0', 'count': '1',
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert '/admin/attacks' in resp.headers['Location']
        with app.app_context():
            e = AttackEvent.query.filter_by(ip_address='55.66.77.88').first()
            assert e is not None
            assert e.severity == 'high'
            assert e.honeypot_service == 'ssh'
            assert e.signature == 'brute_force'
            assert e.headers['User-Agent'] == 'CustomUA/1.0'
            assert e.path == '/ssh/auth'
            p = AttackerProfile.query.filter_by(ip_address='55.66.77.88').first()
            assert p.country == 'JP'

    def test_batch_generation(self, client, app, users):
        login(client, 'admin1')
        client.post('/admin/simulate-attack', data={'count': '5'})
        with app.app_context():
            # 全新内存库,5 条均为本次批量生成
            assert AttackEvent.query.count() == 5
            assert AttackerProfile.query.count() >= 1

    def test_count_capped_to_100(self, client, app, users):
        login(client, 'admin1')
        client.post('/admin/simulate-attack', data={'count': '9999'})
        with app.app_context():
            assert AttackEvent.query.count() == 100

    def test_invalid_severity_falls_back(self, client, app, users):
        login(client, 'admin1')
        client.post('/admin/simulate-attack', data={
            'ip': '10.20.30.40', 'severity': 'catastrophic'})
        with app.app_context():
            e = AttackEvent.query.filter_by(ip_address='10.20.30.40').first()
            assert e.severity in ('low', 'medium', 'high')

    def test_viewer_cannot_simulate(self, client, app, users):
        login(client, 'viewer1')
        resp = client.post('/admin/simulate-attack', data={'count': '3'})
        assert resp.status_code == 403
        with app.app_context():
            assert AttackEvent.query.count() == 0


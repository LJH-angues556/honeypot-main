import os
import sys
import tempfile
import time
import json
import hmac
import hashlib
from datetime import datetime, timedelta

import pytest

# 把项目根目录加入 sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions import db as _db
from app.models import User, AttackEvent, AttackerProfile


class TestConfig:
    TESTING = True
    SECRET_KEY = 'test-secret'
    API_SECRET_KEY = 'test-api-secret'
    WTF_CSRF_ENABLED = False  # 测试关闭 CSRF
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_HOST = 'localhost'
    REDIS_PORT = 6379
    REDIS_DB = 0
    REDIS_PASSWORD = None
    REMEMBER_COOKIE_DURATION_DAYS = 7
    REGISTER_ENABLED = False  # 默认关闭注册
    GEOIP_ENABLED = False  # 测试关闭 GeoIP
    THREAT_INTEL_ENABLED = False  # 测试关闭威胁情报
    RATELIMIT_ENABLED = False  # 测试关闭限流
    RATELIMIT_STORAGE_URI = 'memory://'  # 限流也使用内存,不依赖 Redis
    RQ_ENABLED = False  # 测试不启用 RQ,异步任务降级为同步执行


@pytest.fixture()
def app():
    # 注意:Flask-SQLAlchemy 3.1 在 init_app 时即创建引擎,
    # 测试配置必须在 create_app 阶段传入,之后 from_mapping 不会重建引擎
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


def make_signature(secret: str, timestamp: str, body: bytes) -> str:
    """按 API 规则生成签名"""
    return hmac.new(
        secret.encode(),
        f"{timestamp}{body.decode()}".encode(),
        hashlib.sha256
    ).hexdigest()


# ---------------- 模型 CRUD 测试 ----------------

class TestModelCRUD:
    def test_user_create_and_password(self, app):
        with app.app_context():
            u = User(username='testuser', email='test@example.com', role='viewer')
            u.set_password('mypassword')
            _db.session.add(u)
            _db.session.commit()

            fetched = User.query.filter_by(username='testuser').first()
            assert fetched is not None
            assert fetched.check_password('mypassword') is True
            assert fetched.check_password('wrong') is False
            assert fetched.email == 'test@example.com'

    def test_attack_event_create(self, app):
        with app.app_context():
            p = AttackerProfile(ip_address='1.2.3.4')
            _db.session.add(p)
            _db.session.flush()

            e = AttackEvent(
                ip_address='1.2.3.4',
                method='GET',
                path='/admin',
                severity='high',
                attacker=p,
            )
            _db.session.add(e)
            _db.session.commit()

            fetched = AttackEvent.query.filter_by(ip_address='1.2.3.4').first()
            assert fetched is not None
            assert fetched.severity == 'high'
            assert fetched.attacker.ip_address == '1.2.3.4'
            assert fetched.attacker_id == p.id

    def test_attacker_profile_geoip_fields(self, app):
        with app.app_context():
            p = AttackerProfile(
                ip_address='8.8.8.8',
                country='United States',
                city='Mountain View',
                asn='AS15169',
                isp='Google LLC',
            )
            _db.session.add(p)
            _db.session.commit()

            fetched = AttackerProfile.query.filter_by(ip_address='8.8.8.8').first()
            assert fetched.country == 'United States'
            assert fetched.city == 'Mountain View'


# ---------------- API 签名验证测试 ----------------

class TestAPISignature:
    def test_missing_signature_returns_401(self, client):
        resp = client.post('/api/capture', json={'service': 'web'})
        assert resp.status_code == 401

    def test_wrong_signature_returns_401(self, client):
        body = b'{"service": "web"}'
        resp = client.post(
            '/api/capture',
            data=body,
            content_type='application/json',
            headers={
                'X-API-Signature': 'badsignature',
                'X-API-Timestamp': str(int(time.time())),
            },
        )
        assert resp.status_code == 401

    def test_expired_timestamp_returns_401(self, client):
        body = b'{"service": "web"}'
        old_ts = str(int(time.time()) - 400)  # 400 秒前,超出 5 分钟窗口
        sig = make_signature('test-api-secret', old_ts, body)
        resp = client.post(
            '/api/capture',
            data=body,
            content_type='application/json',
            headers={
                'X-API-Signature': sig,
                'X-API-Timestamp': old_ts,
            },
        )
        assert resp.status_code == 401

    def test_valid_signature_returns_200(self, client, app):
        body = b'{"service": "web", "severity": "high"}'
        ts = str(int(time.time()))
        sig = make_signature('test-api-secret', ts, body)
        resp = client.post(
            '/api/capture',
            data=body,
            content_type='application/json',
            headers={
                'X-API-Signature': sig,
                'X-API-Timestamp': ts,
                'X-Forwarded-For': '10.0.0.1',
                'User-Agent': 'pytest-agent',
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'ok'
        assert 'event_id' in data

        # 验证数据库里写入了数据
        with app.app_context():
            ev = AttackEvent.query.get(data['event_id'])
            assert ev is not None
            assert ev.ip_address == '10.0.0.1'
            assert ev.severity == 'high'
            assert ev.attacker is not None

    def test_repeat_capture_updates_attacker(self, client, app):
        """同一 IP 两次攻击,不重复创建 attacker_profile"""
        ts = str(int(time.time()))
        for _ in range(2):
            body = b'{"service": "web"}'
            sig = make_signature('test-api-secret', ts, body)
            client.post(
                '/api/capture',
                data=body,
                content_type='application/json',
                headers={
                    'X-API-Signature': sig,
                    'X-API-Timestamp': ts,
                    'X-Forwarded-For': '9.9.9.9',
                },
            )

        with app.app_context():
            assert AttackerProfile.query.filter_by(ip_address='9.9.9.9').count() == 1
            assert AttackEvent.query.filter_by(ip_address='9.9.9.9').count() == 2


# ---------------- 认证流程测试 ----------------

class TestAuth:
    def test_login_page_renders(self, client):
        resp = client.get('/login')
        assert resp.status_code == 200

    def test_login_success_redirects_to_dashboard(self, client, admin_user):
        resp = client.post('/login', data={
            'username': 'admin',
            'password': 'password123',
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert '/admin/dashboard' in resp.headers['Location']

    def test_login_wrong_password(self, client, admin_user):
        resp = client.post('/login', data={
            'username': 'admin',
            'password': 'wrongpassword',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert '用户名或密码错误'.encode() in resp.data

    def test_login_nonexistent_user(self, client):
        resp = client.post('/login', data={
            'username': 'nobody',
            'password': 'whatever',
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert '用户名或密码错误'.encode() in resp.data

    def test_dashboard_requires_login(self, client):
        resp = client.get('/admin/dashboard', follow_redirects=False)
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_dashboard_with_login(self, client, admin_user):
        client.post('/login', data={
            'username': 'admin',
            'password': 'password123',
        })
        resp = client.get('/admin/dashboard')
        assert resp.status_code == 200

    def test_logout(self, client, admin_user):
        client.post('/login', data={
            'username': 'admin',
            'password': 'password123',
        })
        resp = client.get('/logout', follow_redirects=False)
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

        # 退出后再访问 dashboard 应该重定向
        resp = client.get('/admin/dashboard', follow_redirects=False)
        assert resp.status_code == 302


# ---------------- 任务1.1 管理员权限隔离 ----------------

@pytest.fixture()
def normal_user(app):
    with app.app_context():
        u = User(username='normal', email='normal@test.com', role='viewer')
        u.set_password('password123')
        _db.session.add(u)
        _db.session.commit()
        return u


@pytest.fixture()
def manager_user(app):
    """普通管理员(admin):可写业务数据,但不能管用户/系统设置。"""
    with app.app_context():
        u = User(username='manager', email='manager@test.com', role='admin')
        u.set_password('password123')
        _db.session.add(u)
        _db.session.commit()
        return u


def login(client, username='normal', password='password123'):
    return client.post('/login', data={'username': username, 'password': password})


class TestAdminAccessControl:
    """角色权限矩阵:viewer 只读、admin 可写、super_admin 全权。"""

    # viewer 可访问的只读页面
    VIEW_PAGES = [
        '/admin/dashboard',
        '/admin/attackers',
        '/admin/attacks',
        '/admin/stats',
        '/admin/database',
        '/admin/map',
        '/admin/settings',
        '/admin/blacklist',
        '/admin/nodes',
        '/admin/alerts',
        '/admin/alert-history',
        '/admin/audit-logs',
    ]
    # 仅超级管理员可访问
    SUPER_ONLY_PAGES = [
        '/admin/system-settings',
        '/admin/users',
    ]

    def test_viewer_can_view_read_pages(self, client, normal_user):
        login(client)
        for path in self.VIEW_PAGES:
            assert client.get(path).status_code == 200, path

    def test_viewer_403_on_super_pages(self, client, normal_user):
        login(client)
        for path in self.SUPER_ONLY_PAGES:
            assert client.get(path).status_code == 403, path

    def test_admin_403_on_super_pages(self, client, manager_user):
        login(client, 'manager')
        for path in self.SUPER_ONLY_PAGES:
            assert client.get(path).status_code == 403, path

    def test_normal_user_gets_403_on_admin_pages(self, client, normal_user):
        # 兼容旧用例名:viewer 访问超管页仍 403
        login(client)
        for path in self.SUPER_ONLY_PAGES:
            assert client.get(path).status_code == 403, path

    def test_normal_user_403_on_simulate_post(self, client, normal_user):
        login(client)
        resp = client.post('/admin/simulate-attack')
        assert resp.status_code == 403

    def test_viewer_can_export_readonly(self, client, normal_user):
        # 导出属于只读操作,viewer 允许
        login(client)
        assert client.get('/admin/export-stats').status_code == 200

    def test_viewer_403_on_write_posts(self, client, normal_user):
        login(client)
        assert client.post('/admin/simulate-attack').status_code == 403
        assert client.post('/admin/nodes/create', data={'name': 'x'}).status_code == 403
        assert client.get('/admin/users').status_code == 403

    def test_admin_can_access_all_pages(self, client, admin_user):
        login(client, 'admin')
        for path in self.VIEW_PAGES + self.SUPER_ONLY_PAGES:
            assert client.get(path).status_code == 200, path

    def test_anonymous_redirected_to_login(self, client):
        resp = client.get('/admin/dashboard', follow_redirects=False)
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']


# ---------------- 任务1.3 注册管控 ----------------

class TestRegisterControl:
    def test_register_disabled_by_default_returns_404(self, client, app):
        # TestConfig 默认 REGISTER_ENABLED = False
        app.config['REGISTER_ENABLED'] = False
        assert client.get('/register').status_code == 404
        assert client.post('/register', data={
            'username': 'newbie',
            'email': 'new@test.com',
            'password': 'password123',
        }).status_code == 404

    def test_register_enabled_returns_200(self, client, app):
        app.config['REGISTER_ENABLED'] = True
        assert client.get('/register').status_code == 200

    def test_login_page_hides_register_link_when_disabled(self, client, app):
        app.config['REGISTER_ENABLED'] = False
        resp = client.get('/login')
        assert b'/register' not in resp.data
        assert '注册账号'.encode() not in resp.data

    def test_login_page_shows_register_link_when_enabled(self, client, app):
        app.config['REGISTER_ENABLED'] = True
        resp = client.get('/login')
        assert b'/register' in resp.data


# ---------------- 任务1.4 错误页 ----------------

class TestErrorPages:
    def test_404_page_renders(self, client):
        resp = client.get('/this-path-does-not-exist')
        assert resp.status_code == 404

    def test_403_page_renders_for_viewer_on_super_page(self, client, normal_user):
        login(client)
        resp = client.get('/admin/users')
        assert resp.status_code == 403
        assert '403'.encode() in resp.data


# ---------------- 任务1.5 攻击事件详情页 ----------------

class TestAttackDetailPage:
    def _create_event(self, app):
        with app.app_context():
            p = AttackerProfile(ip_address='5.5.5.5')
            _db.session.add(p)
            _db.session.flush()
            e = AttackEvent(
                ip_address='5.5.5.5',
                method='POST',
                path='/login',
                severity='critical',
                signature='sql_injection',
                honeypot_service='web',
                headers={'User-Agent': 'pytest'},
                payload={'username': "admin' OR 1=1"},
                attacker=p,
            )
            _db.session.add(e)
            _db.session.commit()
            return e.id

    def test_anonymous_redirect(self, client, app):
        event_id = self._create_event(app)
        resp = client.get(f'/admin/attacks/{event_id}', follow_redirects=False)
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_viewer_can_view_detail(self, client, normal_user, app):
        event_id = self._create_event(app)
        login(client)
        resp = client.get(f'/admin/attacks/{event_id}')
        assert resp.status_code == 200
        assert b'5.5.5.5' in resp.data

    def test_admin_sees_detail(self, client, admin_user, app):
        event_id = self._create_event(app)
        login(client, 'admin')
        resp = client.get(f'/admin/attacks/{event_id}')
        assert resp.status_code == 200
        assert b'5.5.5.5' in resp.data
        assert b'sql_injection' in resp.data

    def test_nonexistent_event_404(self, client, admin_user):
        login(client, 'admin')
        assert client.get('/admin/attacks/99999').status_code == 404


class TestChartPagesWithData:
    """回归:有聚合数据时图表页的 tojson 不能因 Row 不可序列化而 500"""

    def test_dashboard_and_stats_render_with_data(self, client, admin_user, app):
        with app.app_context():
            p = AttackerProfile(ip_address='7.7.7.7', country='CN')
            _db.session.add(p)
            _db.session.flush()
            _db.session.add(AttackEvent(
                ip_address='7.7.7.7', method='GET', path='/', severity='high',
                honeypot_service='web', attacker=p,
            ))
            _db.session.commit()

        login(client, 'admin')
        assert client.get('/admin/dashboard').status_code == 200
        assert client.get('/admin/stats').status_code == 200
        assert client.get('/admin/map').status_code == 200


# ======================================================================
# 第二阶段测试
# ======================================================================

def signed_post(client, path, payload, extra_headers=None):
    """按平台 HMAC 规则发 JSON 请求(签名内容 = timestamp + 原始 body)。"""
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    sig = make_signature('test-api-secret', ts, body)
    headers = {'X-API-Signature': sig, 'X-API-Timestamp': ts}
    if extra_headers:
        headers.update(extra_headers)
    return client.post(path, data=body, content_type='application/json', headers=headers)


# ---------------- 2.7 IP 黑名单 ----------------

class TestIPBlacklist:
    def _make_profile(self, app, ip='6.6.6.6'):
        with app.app_context():
            p = AttackerProfile(ip_address=ip)
            _db.session.add(p)
            _db.session.commit()
            return p.id

    def test_blacklist_page_admin_200(self, client, admin_user):
        login(client, 'admin')
        assert client.get('/admin/blacklist').status_code == 200

    def test_block_and_unblock_flow(self, client, admin_user, app):
        pid = self._make_profile(app)
        login(client, 'admin')

        resp = client.post(f'/admin/attackers/{pid}/block',
                           data={'block_reason': 'SQL 注入扫描'}, follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            p = AttackerProfile.query.get(pid)
            assert p.is_blocked is True
            assert p.block_reason == 'SQL 注入扫描'
            assert p.blocked_at is not None

        resp = client.post(f'/admin/attackers/{pid}/unblock', follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            p = AttackerProfile.query.get(pid)
            assert p.is_blocked is False
            assert p.block_reason is None

    def test_batch_unblock(self, client, admin_user, app):
        ids = [self._make_profile(app, f'6.6.6.{i}') for i in range(2)]
        with app.app_context():
            for pid in ids:
                p = AttackerProfile.query.get(pid)
                p.is_blocked = True
            _db.session.commit()

        login(client, 'admin')
        resp = client.post('/admin/blacklist/unblock',
                           data={'ids': [str(ids[0]), str(ids[1])]})
        assert resp.status_code == 302
        with app.app_context():
            assert all(not AttackerProfile.query.get(pid).is_blocked for pid in ids)

    def test_export_txt_and_csv(self, client, admin_user, app):
        pid = self._make_profile(app, ip='6.6.6.9')
        with app.app_context():
            p = AttackerProfile.query.get(pid)
            p.is_blocked = True
            p.block_reason = 'xss'
            p.blocked_at = datetime.utcnow()
            _db.session.commit()

        login(client, 'admin')
        txt = client.get('/admin/blacklist/export?format=txt')
        assert txt.status_code == 200
        assert b'6.6.6.9' in txt.data

        csv_resp = client.get('/admin/blacklist/export?format=csv')
        assert csv_resp.status_code == 200
        assert csv_resp.data.startswith(b'\xef\xbb\xbf')  # UTF-8 BOM,Excel 友好
        assert 'ip'.encode() in csv_resp.data
        assert b'6.6.6.9' in csv_resp.data

    def test_blacklist_page_lists_blocked_ip(self, client, admin_user, app):
        pid = self._make_profile(app, ip='6.6.6.10')
        with app.app_context():
            AttackerProfile.query.get(pid).is_blocked = True
            _db.session.commit()
        login(client, 'admin')
        assert b'6.6.6.10' in client.get('/admin/blacklist').data


# ---------------- 2.6 系统设置即时生效 ----------------

class TestSystemSettings:
    def test_admin_page_200(self, client, admin_user):
        login(client, 'admin')
        assert client.get('/admin/system-settings').status_code == 200

    def test_save_then_register_opens(self, client, admin_user):
        login(client, 'admin')
        resp = client.post('/admin/system-settings', data={
            'register_enabled': 'on',
            'geoip_enabled': 'on',
            'data_retention_days': '30',
            'smtp_port': '587',
            'api_rate_limit': '100 per minute',
            'daily_report_time': '09:00',
            'smtp_host': '', 'smtp_username': '', 'smtp_sender': '',
        }, follow_redirects=False)
        assert resp.status_code == 302
        # 已登录用户访问 /register 会跳仪表盘,先退出再验证开关已放开
        client.get('/logout')
        assert client.get('/register').status_code == 200

    def test_save_off_then_register_404(self, client, admin_user):
        login(client, 'admin')
        client.post('/admin/system-settings', data={
            'data_retention_days': '30', 'smtp_port': '587',
            'api_rate_limit': '100 per minute', 'daily_report_time': '09:00',
        })
        assert client.get('/register').status_code == 404

    def test_test_email_requires_address(self, client, admin_user):
        login(client, 'admin')
        resp = client.post('/admin/system-settings/test-email', data={},
                           follow_redirects=True)
        assert resp.status_code == 200
        assert '请输入收件邮箱'.encode() in resp.data


# ---------------- 2.3 邮件通知 ----------------

class TestEmailUtils:
    def test_smtp_disabled_by_default(self, app):
        from app import email_utils
        with app.app_context():
            assert email_utils.smtp_enabled() is False
            # 未启用时不发邮件,返回 False 且不抛异常
            assert email_utils.send_email('a@b.com', 's', '<p>x</p>') is False

    def test_send_email_uses_saved_smtp(self, app, admin_user, monkeypatch):
        from app import email_utils
        from app.settings_store import set_setting
        sent = []
        with app.app_context():
            set_setting('smtp_enabled', True)
            set_setting('smtp_host', 'smtp.test.local')
            monkeypatch.setattr(email_utils.mail, 'send', lambda msg: sent.append(msg))

            ok = email_utils.send_email('admin@test.com', '测试', '<p>hello</p>')
            assert ok is True
            assert len(sent) == 1
            assert sent[0].recipients == ['admin@test.com']
            # 系统设置中的 SMTP host 已覆盖环境配置
            from flask import current_app
            assert current_app.config['MAIL_SERVER'] == 'smtp.test.local'

    def test_send_failure_never_raises(self, app, admin_user, monkeypatch):
        from app import email_utils
        from app.settings_store import set_setting
        with app.app_context():
            set_setting('smtp_enabled', True)

            def boom(msg):
                raise RuntimeError('smtp down')

            monkeypatch.setattr(email_utils.mail, 'send', boom)
            assert email_utils.send_email('admin@test.com', 's', '<p>x</p>') is False

    def test_daily_report_sent_to_admin(self, app, admin_user, monkeypatch):
        from app import email_utils
        from app.settings_store import set_setting
        with app.app_context():
            set_setting('smtp_enabled', True)
            yesterday = datetime.utcnow().date() - timedelta(days=1)
            p = AttackerProfile(ip_address='8.8.4.4', first_seen=datetime.utcnow())
            _db.session.add(p)
            _db.session.flush()
            _db.session.add(AttackEvent(
                ip_address='8.8.4.4', method='GET', path='/wp-login.php',
                severity='low', honeypot_service='http-wordpress',
                timestamp=datetime.utcnow() - timedelta(days=1), attacker=p,
            ))
            _db.session.commit()

            sent = []
            monkeypatch.setattr(email_utils.mail, 'send', lambda msg: sent.append(msg))
            count = email_utils.send_daily_report(yesterday)
            assert count == 1
            assert len(sent) == 1
            assert sent[0].recipients == ['admin@test.com']
            assert '每日攻击报告' in sent[0].html

    def test_high_severity_alert(self, app, admin_user, monkeypatch):
        from app import email_utils
        from app.settings_store import set_setting
        with app.app_context():
            set_setting('smtp_enabled', True)
            set_setting('email_alerts_enabled', True)
            p = AttackerProfile(ip_address='8.8.5.5')
            _db.session.add(p)
            _db.session.flush()
            event = AttackEvent(
                ip_address='8.8.5.5', method='POST', path='/login',
                severity='high', signature='sql_injection', attacker=p,
            )
            _db.session.add(event)
            _db.session.commit()

            sent = []
            monkeypatch.setattr(email_utils.mail, 'send', lambda msg: sent.append(msg))
            assert email_utils.send_attack_alert(event) is True
            assert len(sent) == 1

    def test_low_severity_no_alert(self, app, admin_user):
        from app import email_utils
        from app.settings_store import set_setting
        with app.app_context():
            set_setting('email_alerts_enabled', True)
            p = AttackerProfile(ip_address='8.8.6.6')
            _db.session.add(p)
            _db.session.flush()
            event = AttackEvent(
                ip_address='8.8.6.6', method='GET', path='/',
                severity='low', attacker=p,
            )
            _db.session.add(event)
            _db.session.commit()
            assert email_utils.send_attack_alert(event) is False


# ---------------- 2.4 密码找回 ----------------

class TestPasswordReset:
    def test_login_page_has_forgot_link(self, client):
        assert b'/forgot-password' in client.get('/login').data

    def test_forgot_page_renders(self, client):
        assert client.get('/forgot-password').status_code == 200

    def test_forgot_existing_email_unified_message(self, client, admin_user, monkeypatch):
        from app import email_utils
        monkeypatch.setattr(email_utils, 'send_email', lambda *a, **k: True)
        resp = client.post('/forgot-password', data={'email': 'admin@test.com'},
                           follow_redirects=False)
        assert resp.status_code == 302
        flash_page = client.get('/login')
        assert '如果该邮箱已注册'.encode() in flash_page.data

    def test_forgot_nonexistent_email_same_message(self, client, monkeypatch):
        from app import email_utils
        called = []
        monkeypatch.setattr(email_utils, 'send_email',
                            lambda *a, **k: called.append(1) or True)
        client.post('/forgot-password', data={'email': 'nobody@test.com'})
        assert called == []  # 不存在的邮箱不发信
        assert '如果该邮箱已注册'.encode() in client.get('/login').data

    def test_full_reset_flow_and_one_time_token(self, client, app, admin_user):
        from app.blueprints.auth import generate_reset_token
        with app.app_context():
            u = User.query.filter_by(username='admin').first()
            token = generate_reset_token(u)

        assert client.get(f'/reset-password/{token}').status_code == 200
        resp = client.post(f'/reset-password/{token}', data={
            'password': 'newpass456', 'password2': 'newpass456',
        }, follow_redirects=False)
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

        with app.app_context():
            assert User.query.filter_by(username='admin').first() \
                .check_password('newpass456') is True

        # 旧令牌一次性失效:密码已改,版本号不匹配
        client.post('/login', data={'username': 'admin', 'password': 'newpass456'})
        # 用新会话(未登录)再访问旧链接
        client.get('/logout')
        resp = client.get(f'/reset-password/{token}', follow_redirects=False)
        assert resp.status_code == 302
        assert '/forgot-password' in resp.headers['Location']

    def test_garbage_token_rejected(self, client):
        resp = client.get('/reset-password/not-a-valid-token', follow_redirects=False)
        assert resp.status_code == 302
        assert '/forgot-password' in resp.headers['Location']

    def test_expired_token_rejected(self, app, admin_user):
        import itsdangerous
        from itsdangerous import URLSafeTimedSerializer
        import app.blueprints.auth as auth_mod
        with app.app_context():
            u = User.query.filter_by(username='admin').first()
            s = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='password-reset')
            token = s.dumps({'uid': u.id, 'v': auth_mod._password_version(u)})

        # 模拟签名已过 max_age:loads 抛 SignatureExpired
        orig = URLSafeTimedSerializer.loads

        def expired_loads(self, s, max_age=None):
            raise itsdangerous.SignatureExpired('expired')

        URLSafeTimedSerializer.loads = expired_loads
        try:
            with app.app_context():
                user, error = auth_mod.load_reset_user(token)
                assert user is None and error == 'expired'
        finally:
            URLSafeTimedSerializer.loads = orig


# ---------------- 2.5 RQ 队列降级 ----------------

class TestAsyncQueue:
    def test_queue_disabled_in_tests(self, app):
        assert app.task_queue is None

    def test_enqueue_runs_synchronously(self, app):
        from app.async_utils import enqueue
        marker = []
        with app.app_context():
            enqueue(lambda: marker.append('done'))
        assert marker == ['done']

    def test_enrich_geoip_job_safe_when_disabled(self, app):
        from app.jobs import enrich_geoip
        with app.app_context():
            p = AttackerProfile(ip_address='9.9.9.9')
            _db.session.add(p)
            _db.session.flush()
            e = AttackEvent(ip_address='9.9.9.9', method='GET', path='/',
                            attacker=p)
            _db.session.add(e)
            _db.session.commit()
            # GEOIP_ENABLED=False:任务静默跳过,不报错
            enrich_geoip(e.id)
            assert AttackerProfile.query.get(p.id).country is None


# ---------------- 2.2 蜜罐节点 ----------------

class TestNodeAPI:
    def test_register_requires_signature(self, client):
        resp = client.post('/api/node/register', json={'name': 'n1'})
        assert resp.status_code == 401

    def test_register_requires_name(self, client):
        resp = signed_post(client, '/api/node/register', {})
        assert resp.status_code == 400

    def test_register_and_idempotent_reregister(self, client, app):
        resp = signed_post(client, '/api/node/register',
                           {'name': 'hp-1', 'service_type': 'http'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data['node_key']) == 64
        assert data['heartbeat_timeout'] == 300
        key1 = data['node_key']

        # 同名重复注册(容器重建)复用同一 node_key
        resp2 = signed_post(client, '/api/node/register',
                            {'name': 'hp-1', 'service_type': 'http'})
        assert resp2.get_json()['node_key'] == key1

        from app.models import HoneypotNode
        with app.app_context():
            assert HoneypotNode.query.count() == 1

    def test_heartbeat_flow(self, client, app):
        key = signed_post(client, '/api/node/register',
                          {'name': 'hp-2'}).get_json()['node_key']

        assert client.post('/api/node/heartbeat', json={}).status_code == 401
        assert client.post('/api/node/heartbeat',
                           json={'node_key': 'bad-key'}).status_code == 401

        resp = client.post('/api/node/heartbeat',
                           headers={'X-Node-Key': key})
        assert resp.status_code == 200
        assert resp.get_json()['status'] == 'ok'

        from app.models import HoneypotNode
        with app.app_context():
            node = HoneypotNode.query.filter_by(name='hp-2').first()
            assert node.is_online is True
            assert node.last_heartbeat is not None

    def test_node_offline_without_heartbeat(self, client, app):
        from app.models import HoneypotNode
        with app.app_context():
            node = HoneypotNode(name='hp-3', node_key='x' * 64,
                                service_type='http', status='offline')
            _db.session.add(node)
            _db.session.commit()
            assert node.is_online is False
            stale = HoneypotNode(name='hp-4', node_key='y' * 64,
                                 service_type='http', status='online',
                                 last_heartbeat=datetime.utcnow() - timedelta(minutes=6))
            _db.session.add(stale)
            _db.session.commit()
            assert stale.is_online is False

    def test_capture_links_node(self, client, app):
        key = signed_post(client, '/api/node/register',
                          {'name': 'hp-5'}).get_json()['node_key']
        client.post('/api/node/heartbeat', headers={'X-Node-Key': key})

        resp = signed_post(
            client, '/api/capture',
            {'service': 'http-phpmyadmin', 'severity': 'low',
             'path': '/phpmyadmin/index.php', 'method': 'POST',
             'payload': {'username': 'root', 'password': 'toor'}},
            extra_headers={'X-Node-Key': key},
        )
        assert resp.status_code == 200
        event_id = resp.get_json()['event_id']
        with app.app_context():
            ev = AttackEvent.query.get(event_id)
            assert ev.node is not None
            assert ev.node.name == 'hp-5'
            # node_key 仅用于鉴权,不应写入 payload
            assert 'node_key' not in (ev.payload or {})

    def test_capture_trusts_reported_client_ip(self, client, app):
        key = signed_post(client, '/api/node/register',
                          {'name': 'hp-6'}).get_json()['node_key']
        resp = signed_post(
            client, '/api/capture',
            {'service': 'http-admin', 'client_ip': '203.0.113.77',
             'method': 'GET', 'path': '/admin/login'},
            extra_headers={'X-Node-Key': key},
        )
        event_id = resp.get_json()['event_id']
        with app.app_context():
            assert AttackEvent.query.get(event_id).ip_address == '203.0.113.77'

    def test_capture_rejects_invalid_client_ip(self, client, app):
        key = signed_post(client, '/api/node/register',
                          {'name': 'hp-7'}).get_json()['node_key']
        resp = signed_post(
            client, '/api/capture',
            {'service': 'http-admin', 'client_ip': 'not-an-ip',
             'method': 'GET', 'path': '/x'},
            extra_headers={'X-Node-Key': key, 'X-Forwarded-For': '198.51.100.9'},
        )
        event_id = resp.get_json()['event_id']
        with app.app_context():
            # 非法 client_ip 被忽略,回退 X-Forwarded-For
            assert AttackEvent.query.get(event_id).ip_address == '198.51.100.9'


class TestNodeAdminPages:
    def test_nodes_page_200(self, client, admin_user):
        login(client, 'admin')
        assert client.get('/admin/nodes').status_code == 200

    def test_create_and_delete_node(self, client, admin_user, app):
        from app.models import HoneypotNode
        login(client, 'admin')
        resp = client.post('/admin/nodes/create',
                           data={'name': 'web-node', 'service_type': 'http'},
                           follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            node = HoneypotNode.query.filter_by(name='web-node').first()
            assert node is not None
            assert len(node.node_key) == 64
            node_id = node.id

        resp = client.post(f'/admin/nodes/{node_id}/delete', follow_redirects=False)
        assert resp.status_code == 302
        with app.app_context():
            assert HoneypotNode.query.get(node_id) is None

    def test_duplicate_name_rejected(self, client, admin_user):
        login(client, 'admin')
        client.post('/admin/nodes/create', data={'name': 'dup-node'})
        resp = client.post('/admin/nodes/create', data={'name': 'dup-node'},
                           follow_redirects=True)
        assert '已存在'.encode() in resp.data


# ---------------- 2.1 HTTP 蜜罐攻击检测(纯函数) ----------------

class TestHoneypotDetection:
    def test_sql_injection_detected(self):
        from honeypots.http_honeypot import detect_signature
        sig, sev = detect_signature("/login?id=1' OR '1'='1")
        assert sig == 'sql_injection' and sev == 'high'
        sig, _ = detect_signature('/search', 'q=UNION SELECT password FROM users')
        assert sig == 'sql_injection'
        sig, _ = detect_signature('/x', "name=admin' OR 1=1-- ")
        assert sig == 'sql_injection'

    def test_xss_detected(self):
        from honeypots.http_honeypot import detect_signature
        sig, sev = detect_signature('/c', '<script>document.cookie</script>')
        assert sig == 'xss_attempt' and sev == 'medium'
        sig, _ = detect_signature('/c', '<img src=x onerror=alert(1)>')
        assert sig == 'xss_attempt'

    def test_path_traversal_detected(self):
        from honeypots.http_honeypot import detect_signature
        sig, sev = detect_signature('/file?path=../../../../etc/passwd')
        assert sig == 'path_traversal' and sev == 'medium'

    def test_url_encoded_traversal_detected(self):
        from honeypots.http_honeypot import detect_signature
        sig, _ = detect_signature('/%2e%2e%2f%2e%2e%2fetc/passwd')
        assert sig == 'path_traversal'

    def test_normal_login_not_flagged(self):
        from honeypots.http_honeypot import detect_signature
        assert detect_signature('/wp-login.php', 'admin', 'CorrectHorse9') == (None, None)

    def test_parse_ports(self):
        from honeypots.http_honeypot import parse_ports
        assert parse_ports('8080:phpmyadmin,8081:wordpress') == \
            [(8080, 'phpmyadmin'), (8081, 'wordpress')]
        # 无类型时回退 admin,未知类型同样回退
        assert parse_ports('9000,9001:weird') == [(9000, 'admin'), (9001, 'admin')]

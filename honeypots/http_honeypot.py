"""独立 HTTP 蜜罐服务

与主平台解耦:不导入 app 包,仅依赖 flask + requests,可单独拷贝到其他主机运行。
捕获到的凭据与攻击行为通过 HMAC 签名上报到主平台 /api/capture,
启动时自动注册节点并定时心跳。

环境变量:
  HONEYPOT_API_URL    平台基础地址,默认 http://app:5000
  HONEYPOT_API_SECRET HMAC 密钥(回退读取 API_SECRET_KEY,须与平台一致)
  HONEYPOT_NODE_NAME  节点名称,默认 http-honeypot
  HONEYPOT_PORTS      端口:诱饵类型映射,如 "8080:phpmyadmin,8081:wordpress,8082:admin"
  HONEYPOT_BIND       监听地址,默认 0.0.0.0
"""
import hashlib
import hmac
import logging
import os
import re
import threading
import time
from urllib.parse import unquote_plus

import requests
from flask import Flask, request, render_template, make_response

from ._reporter import PlatformReporter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [http-honeypot] %(levelname)s %(message)s',
)
log = logging.getLogger('http_honeypot')

API_URL = os.getenv('HONEYPOT_API_URL', 'http://app:5000').rstrip('/')
API_SECRET = os.getenv('HONEYPOT_API_SECRET') or os.getenv('API_SECRET_KEY', '')
NODE_NAME = os.getenv('HONEYPOT_NODE_NAME', 'http-honeypot')
BIND = os.getenv('HONEYPOT_BIND', '0.0.0.0')

# (端口, 诱饵类型);默认 8080 通用后台
DEFAULT_PORTS = '8080:admin'

DECOY_META = {
    'phpmyadmin': {'template': 'phpmyadmin.html', 'login_path': '/phpmyadmin/index.php',
                   'server': 'Apache/2.4.41 (Ubuntu)', 'powered': 'PHP/7.4.3'},
    'wordpress': {'template': 'wordpress.html', 'login_path': '/wp-login.php',
                  'server': 'nginx/1.18.0', 'powered': 'PHP/8.0.30'},
    'admin': {'template': 'admin.html', 'login_path': '/admin/login',
              'server': 'Apache/2.4.58', 'powered': None},
}

# ---------------- 攻击特征检测 ----------------

ATTACK_PATTERNS = [
    ('sql_injection', re.compile(
        r"(?i)(union[\s/*]+select|'\s*or\s*'?\d+'?\s*=\s*'?\d|"
        r"sleep\s*\(\d+\)|benchmark\s*\(|information_schema|"
        r";\s*drop\s+table|--\s|'\s*or\s+1\s*=\s*1|waitfor\s+delay)")),
    ('xss_attempt', re.compile(
        r"(?i)(<script[\s>]|javascript:|onerror\s*=|onload\s*=|"
        r"<img[^>]+src\s*=|<svg[^>]*on\w+|document\.cookie)")),
    ('path_traversal', re.compile(
        r"(?i)(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini|"
        r"%2e%2e%2f|%2e%2e/|\.\.%2f|boot\.ini)")),
]

SEVERITY_BY_SIGNATURE = {
    'sql_injection': 'high',
    'xss_attempt': 'medium',
    'path_traversal': 'medium',
    'login_attempt': 'low',
    'probe': 'info',
}


def detect_signature(*texts):
    """在任意文本片段中匹配攻击特征,返回 (signature, severity) 或 (None, None)。"""
    blob = ' '.join(t for t in texts if t)
    blob = unquote_plus(blob)
    for signature, pattern in ATTACK_PATTERNS:
        if pattern.search(blob):
            return signature, SEVERITY_BY_SIGNATURE[signature]
    return None, None


# ---------------- 平台上报客户端 ----------------
# PlatformReporter 已抽出到 honeypots/_reporter.py,各蜜罐复用


# ---------------- 诱饵 Flask 应用 ----------------

def _client_ip():
    xff = (request.headers.get('X-Forwarded-For', '') or '').split(',')[0].strip()
    return xff or request.remote_addr or '0.0.0.0'


def _base_event(service, severity='low', signature=None, extra=None):
    event = {
        'service': f'http-{service}',
        'honeypot_type': 'http',
        # 蜜罐看到的真实攻击者 IP(端口映射/Docker NAT 场景下,
        # 平台直接 TCP 对端只会是蜜罐容器地址,必须由此字段透传)
        'client_ip': _client_ip(),
        'method': request.method,
        'path': request.full_path.rstrip('?'),
        'headers': dict(request.headers),
        'severity': severity,
        'signature': signature,
    }
    if extra:
        event.update(extra)
    return event


def create_decoy_app(decoy_type, reporter):
    meta = DECOY_META[decoy_type]
    app = Flask(f'honeypot_{decoy_type}',
                template_folder=os.path.join(os.path.dirname(__file__), 'templates'))

    def _render_login(login_error=False):
        resp = make_response(render_template(
            meta['template'], login_error=login_error,
            login_path=meta['login_path'],
        ))
        resp.headers['Server'] = meta['server']
        if meta['powered']:
            resp.headers['X-Powered-By'] = meta['powered']
        return resp

    def _fake_not_found():
        resp = make_response(
            '<!doctype html><html><head><title>404 Not Found</title></head>'
            '<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>'
            '<hr><address>' + meta['server'] + ' Server at ' +
            request.host.split(':')[0] + ' Port ' + str(request.host.split(':')[-1]) +
            '</address></body></html>', 404)
        resp.headers['Server'] = meta['server']
        return resp

    @app.route('/', methods=['GET'])
    def root():
        # 根路径探测:静默上报后把攻击者引导到登录页
        reporter.report(_base_event(decoy_type, 'info', 'probe'))
        return _render_login()

    @app.route(meta['login_path'], methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            return _render_login()

        username = (request.form.get('username')
                    or request.form.get('user')
                    or request.form.get('pma_username')
                    or request.form.get('log') or '').strip()
        password = (request.form.get('password')
                    or request.form.get('pma_password')
                    or request.form.get('pwd') or '')
        signature, detected_severity = detect_signature(
            request.path, request.query_string.decode(errors='ignore'),
            username, password,
        )
        reporter.report(_base_event(
            decoy_type,
            detected_severity or SEVERITY_BY_SIGNATURE['login_attempt'],
            signature or 'login_attempt',
            {'payload': {'username': username, 'password': password}},
        ))
        # 无论凭据对错都回"登录失败",诱导攻击者继续尝试
        return _render_login(login_error=True)

    @app.route('/<path:any_path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD'])
    def catch_all(any_path):
        # 命中该诱饵自己的登录路径时由上面的规则处理(Flask 优先匹配静态路由)
        body_text = ''
        if request.method in ('POST', 'PUT'):
            body_text = request.get_data(as_text=True)[:2000]
        signature, severity = detect_signature(
            request.path, request.query_string.decode(errors='ignore'), body_text,
        )
        if signature:
            reporter.report(_base_event(
                decoy_type, severity, signature,
                {'payload': {'raw_body': body_text[:500]}},
            ))
            return _fake_not_found()
        # 普通路径探测,低噪上报
        reporter.report(_base_event(decoy_type, 'info', 'probe'))
        return _fake_not_found()

    return app


def parse_ports(spec):
    result = []
    for item in spec.split(','):
        item = item.strip()
        if not item:
            continue
        if ':' in item:
            port, decoy = item.split(':', 1)
        else:
            port, decoy = item, 'admin'
        port, decoy = int(port), decoy.strip().lower()
        if decoy not in DECOY_META:
            log.warning('未知诱饵类型 %s,回退为 admin', decoy)
            decoy = 'admin'
        result.append((port, decoy))
    return result or parse_ports(DEFAULT_PORTS)


def main():
    if not API_SECRET:
        log.warning('API_SECRET_KEY 未配置,攻击数据将无法通过平台鉴权(请检查环境变量)')
    reporter = PlatformReporter(API_URL, API_SECRET, NODE_NAME, 'http')

    # 节点注册(同步尝试一次,失败后心跳线程继续重试)
    reporter.register()
    reporter.start_heartbeat()

    from werkzeug.serving import make_server

    servers = []
    for port, decoy in parse_ports(os.getenv('HONEYPOT_PORTS', DEFAULT_PORTS)):
        app = create_decoy_app(decoy, reporter)
        srv = make_server(BIND, port, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        log.info('诱饵 %s 监听 %s:%d (登录入口 %s)',
                 decoy, BIND, port, DECOY_META[decoy]['login_path'])

    log.info('HTTP 蜜罐已启动,上报地址 %s,节点名 %s', API_URL, NODE_NAME)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log.info('蜜罐退出')
        for srv in servers:
            srv.shutdown()
        reporter.stop()


if __name__ == '__main__':
    main()

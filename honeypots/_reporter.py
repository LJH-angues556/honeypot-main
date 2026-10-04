"""蜜罐上报到主平台的公共客户端。

所有蜜罐(HTTP/SSH/Telnet/Redis)复用本类:
- 带 HMAC-SHA256 签名的上报(与平台 /api/capture 鉴权一致)
- 启动时自动注册节点 + 每 60 秒心跳
- 上报异步线程,失败指数退避重试,绝不阻塞诱饵自身
"""
import hashlib
import hmac
import logging
import threading
import time

import requests

log = logging.getLogger('honeypot.reporter')


class PlatformReporter:
    def __init__(self, base_url, secret, node_name, service_type):
        self.base_url = base_url.rstrip('/')
        self.secret = secret
        self.node_name = node_name
        self.service_type = service_type
        self.node_key = None
        self._stop = threading.Event()

    def _signed_post(self, path, payload, timeout=5, retries=3):
        body = requests.compat.json.JSONEncoder().encode(payload).encode()
        timestamp = str(int(time.time()))
        signature = hmac.new(
            self.secret.encode(), timestamp.encode() + body, hashlib.sha256
        ).hexdigest()
        headers = {
            'Content-Type': 'application/json',
            'X-API-Timestamp': timestamp,
            'X-API-Signature': signature,
        }
        if self.node_key and path == '/api/capture':
            headers['X-Node-Key'] = self.node_key
        url = self.base_url + path
        for attempt in range(retries):
            try:
                resp = requests.post(url, data=body, headers=headers, timeout=timeout)
                if resp.status_code == 200:
                    return resp.json()
                log.warning('上报 %s 返回 HTTP %s: %s', path, resp.status_code, resp.text[:200])
            except requests.RequestException as e:
                log.warning('上报 %s 失败(第 %d 次): %s', path, attempt + 1, e)
            time.sleep(min(2 ** attempt, 5))
        log.error('上报 %s 重试 %d 次后放弃', path, retries)
        return None

    def register(self):
        if not self.secret:
            log.error('未配置 HONEYPOT_API_SECRET/API_SECRET_KEY,无法注册节点')
            return False
        data = self._signed_post('/api/node/register', {
            'name': self.node_name, 'service_type': self.service_type,
        }, retries=5)
        if data and 'node_key' in data:
            self.node_key = data['node_key']
            log.info('节点 [%s] 注册成功 id=%s,心跳间隔 %ss',
                     self.node_name, data.get('node_id'),
                     data.get('heartbeat_interval'))
            return True
        return False

    def heartbeat_loop(self):
        """注册 + 每 60 秒心跳,401 自动重新注册。"""
        while not self._stop.is_set():
            if not self.node_key and not self.register():
                self._stop.wait(30)
                continue
            try:
                resp = requests.post(
                    self.base_url + '/api/node/heartbeat',
                    json={'node_key': self.node_key}, timeout=5,
                )
                if resp.status_code == 401:
                    log.warning('心跳 401,node_key 失效,重新注册')
                    self.node_key = None
                elif resp.status_code != 200:
                    log.warning('心跳返回 HTTP %s', resp.status_code)
            except requests.RequestException as e:
                log.warning('心跳失败: %s', e)
            self._stop.wait(60)

    def start_heartbeat(self):
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()

    def report(self, event):
        """异步线程上报,绝不阻塞诱饵响应。"""
        threading.Thread(target=self._signed_post,
                         args=('/api/capture', event), daemon=True).start()

    def stop(self):
        self._stop.set()

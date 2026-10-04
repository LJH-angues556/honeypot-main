"""实时事件推送(SSE / Server-Sent Events)。

架构:攻击事件入库后向 Redis 频道 honeypot:events 发布一条消息;
仪表盘/事件列表页通过 GET /admin/stream 建立 EventSource 长连接,
经由 Redis pub/sub 跨 gunicorn worker 收到广播。

- Redis 不可用时 publish 静默降级、stream 返回 503(前端 EventSource 自动重连)
- 仅登录用户可建立连接(路由上 @login_required,session cookie 随 EventSource 自动携带)
"""
import json
import logging

import redis
from flask import current_app

from .extensions import db
from .models import AttackEvent, AttackerProfile

log = logging.getLogger('honeypot.realtime')

CHANNEL = 'honeypot:events'
HEARTBEAT_SECONDS = 15  # 周期性心跳注释,防止代理超时断连


def publish_event(payload) -> None:
    """向所有在线后台页面广播一条事件。任何异常都不影响主业务。"""
    try:
        current_app.redis.publish(
            CHANNEL, json.dumps(payload, ensure_ascii=False, default=str))
    except Exception:
        log.debug('SSE publish skipped(Redis 不可用或序列化失败)', exc_info=True)


def build_event_payload(event) -> dict:
    """组装推送给前端的事件摘要(含最新总量,供仪表盘直接更新数字)。"""
    ts = event.timestamp.strftime('%Y-%m-%d %H:%M:%S') if event.timestamp else ''
    return {
        'id': event.id,
        'timestamp': ts,
        'ip_address': event.ip_address,
        'method': event.method or '',
        'path': event.path or '',
        'honeypot_service': event.honeypot_service or '',
        'signature': event.signature or '',
        'severity': event.severity or 'info',
        'totals': {
            'total_attacks': db.session.query(AttackEvent.id).count(),
            'unique_attackers': db.session.query(AttackerProfile.id).count(),
        },
    }


def subscribe():
    """订阅事件频道,返回 Redis pubsub 对象;Redis 不可用时抛出 redis.RedisError。"""
    pubsub = current_app.redis.pubsub()
    pubsub.subscribe(CHANNEL)
    return pubsub


def generate(pubsub):
    """SSE 响应生成器:转发频道消息,空闲时发心跳注释,结束时关闭订阅。"""
    try:
        yield ': connected\n\n'
        while True:
            msg = pubsub.get_message(
                ignore_subscribe_messages=True,
                timeout=HEARTBEAT_SECONDS)
            if msg is not None and msg.get('type') == 'message':
                data = msg.get('data')
                if isinstance(data, bytes):
                    data = data.decode('utf-8', errors='replace')
                yield f'data: {data}\n\n'
            else:
                yield ': ping\n\n'
    finally:
        try:
            pubsub.close()
        except Exception:
            pass

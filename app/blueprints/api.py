from datetime import datetime
import hmac
import hashlib
import secrets
import time

from flask import Blueprint, request, jsonify, current_app
from ..extensions import db, limiter, csrf
from ..models import AttackEvent, AttackerProfile, HoneypotNode
from ..async_utils import enqueue
from ..jobs import enrich_geoip, send_attack_alert as send_alert_job, evaluate_alert_rules


api_bp = Blueprint('api', __name__)
# 该蓝图是蜜罐节点的机器间上报接口,鉴权靠 HMAC 签名而非浏览器 Cookie/表单,
# 无需也不应启用 CSRF 保护(否则所有上报都会被 400 拒绝)
csrf.exempt(api_bp)

HEARTBEAT_INTERVAL = 60   # 节点心跳建议间隔(秒)
HEARTBEAT_TIMEOUT = 300   # 超过该时长无心跳判定离线(秒)


def verify_api_signature():
    """验证API签名"""
    signature = request.headers.get('X-API-Signature')
    timestamp = request.headers.get('X-API-Timestamp')
    
    if not signature or not timestamp:
        return False
    
    # 检查时间戳（5分钟内有效）
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > 300:  # 5分钟
            return False
    except ValueError:
        return False
    
    # 验证签名:签名内容 = timestamp 字节 + 原始请求体字节
    # 注意不能用 f"...{request.get_data()}",那会把 bytes 渲染成 "b'...'" 字面量
    secret = current_app.config.get('API_SECRET_KEY', 'default-secret')
    expected_signature = hmac.new(
        secret.encode(),
        timestamp.encode() + request.get_data(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected_signature)


def get_or_create_attacker(ip_address: str, user_agent: str | None):
    """获取或创建攻击者画像。GeoIP 归属地由 RQ 任务异步补全(见 app/jobs.py)。"""
    profile = AttackerProfile.query.filter_by(ip_address=ip_address).first()
    if profile:
        profile.last_seen = datetime.utcnow()
        if user_agent:
            profile.user_agent = user_agent
        return profile
    profile = AttackerProfile(
        ip_address=ip_address,
        user_agent=user_agent or '',
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db.session.add(profile)
    return profile


def _capture_rate_limit() -> str:
    """限流速率运行时从系统设置读取(可在后台修改,无需重启)。"""
    from ..settings_store import get_setting
    return get_setting('api_rate_limit', '100 per minute')


def _client_ip():
    """取真实客户端 IP(X-Forwarded-For 链取第一个,兜底 remote_addr)。"""
    return ((request.headers.get('X-Forwarded-For', '') or '').split(',')[0].strip()
            or request.remote_addr)


@api_bp.route('/node/register', methods=['POST'])
@limiter.limit("10 per minute")
def node_register():
    """蜜罐节点注册/幂等重注册。平台级 HMAC 鉴权,返回该节点的 node_key。"""
    if not verify_api_signature():
        return jsonify({'error': 'Invalid signature'}), 401
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()[:64]
    if not name:
        return jsonify({'error': 'name is required'}), 400
    service_type = (data.get('service_type') or 'http').strip()[:32] or 'http'

    # 幂等:同名节点重复注册(容器重建/重启)复用既有 node_key,避免堆积
    node = HoneypotNode.query.filter_by(name=name).first()
    if node:
        node.ip_address = _client_ip()
        node.service_type = service_type
        created = False
    else:
        node = HoneypotNode(
            name=name,
            node_key=secrets.token_hex(32),
            ip_address=_client_ip(),
            service_type=service_type,
            status='offline',
        )
        db.session.add(node)
        created = True
    db.session.commit()
    current_app.logger.info('节点 %s 已%s id=%s', name, '注册' if created else '刷新', node.id)
    return jsonify({
        'node_id': node.id,
        'node_key': node.node_key,
        'heartbeat_interval': HEARTBEAT_INTERVAL,
        'heartbeat_timeout': HEARTBEAT_TIMEOUT,
    })


@api_bp.route('/node/heartbeat', methods=['POST'])
@limiter.limit("60 per minute")
def node_heartbeat():
    """节点心跳上报,凭 node_key 鉴权;同时刷新 last_heartbeat 与来源 IP。"""
    data = request.get_json(silent=True) or {}
    node_key = request.headers.get('X-Node-Key') or data.get('node_key')
    if not node_key:
        return jsonify({'error': 'node key required'}), 401
    node = HoneypotNode.query.filter_by(node_key=node_key).first()
    if not node:
        return jsonify({'error': 'invalid node key'}), 401

    node.last_heartbeat = datetime.utcnow()
    node.status = 'online'
    client_ip = _client_ip()
    if client_ip:
        node.ip_address = client_ip
    db.session.commit()
    return jsonify({'status': 'ok', 'server_time': node.last_heartbeat.isoformat()})


@api_bp.route('/capture', methods=['POST'])
@limiter.limit(_capture_rate_limit)
def capture():
    # 验证API签名
    if not verify_api_signature():
        return jsonify({'error': 'Invalid signature'}), 401
    ip_address = _client_ip()
    user_agent = request.headers.get('User-Agent')
    json_payload = request.get_json(silent=True) or {}

    # 节点关联:X-Node-Key 头或 payload.node_key(消费后不落库)
    node_key = request.headers.get('X-Node-Key') or json_payload.pop('node_key', None)
    node = HoneypotNode.query.filter_by(node_key=node_key).first() if node_key else None

    # 可信蜜罐节点透传它看到的真实攻击者 IP(client_ip);
    # 仅接受格式合法的 IP,非法时回退 TCP 对端地址,防止画像被任意伪造
    reported_ip = (json_payload.pop('client_ip', None) or '').strip()
    if reported_ip:
        import ipaddress
        try:
            ipaddress.ip_address(reported_ip)
            ip_address = reported_ip
        except ValueError:
            current_app.logger.warning('忽略非法 client_ip: %r', reported_ip)

    profile = get_or_create_attacker(ip_address, user_agent)

    # 独立蜜罐程序上报时,真实请求的 method/path/headers 放在 payload 里
    event = AttackEvent(
        ip_address=ip_address,
        method=(json_payload.get('method') or request.method)[:16],
        path=(json_payload.get('path') or request.path)[:255],
        headers=(json_payload.get('headers')
                 if isinstance(json_payload.get('headers'), dict)
                 else dict(request.headers)),
        payload=json_payload,
        honeypot_service=json_payload.get('service') or 'web',
        signature=json_payload.get('signature'),
        severity=json_payload.get('severity') or 'low',
        attacker=profile,
        node=node,
    )
    db.session.add(event)
    db.session.commit()

    # 异步处理:GeoIP 归属地补全 + 高危事件邮件告警 + 告警规则评估。
    # RQ 不可用时 enqueue 自动降级为同步执行,异常不影响上报响应。
    try:
        enqueue(enrich_geoip, event.id)
        enqueue(send_alert_job, event.id)
        enqueue(evaluate_alert_rules, event.id)
        # 威胁情报查询(有本地缓存,重复 IP 开销极低)
        from ..jobs import lookup_threat
        enqueue(lookup_threat, event.ip_address)
    except Exception as e:
        current_app.logger.exception('异步任务调度失败: %s', e)

    # SSE 实时推送到在线仪表盘(Redis 不可用时静默跳过)
    try:
        from ..realtime import publish_event, build_event_payload
        publish_event(build_event_payload(event))
    except Exception:
        current_app.logger.debug('SSE 广播失败', exc_info=True)

    return jsonify({'status': 'ok', 'event_id': event.id})



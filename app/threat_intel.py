"""威胁情报对接(任务4.3)

情报源:
1. 开源 feed(零配置、无需 API Key):Spamhaus DROP / EDROP 恶意网段列表
   https://www.spamhaus.org/drop/drop.txt
   https://www.spamhaus.org/drop/edrop.txt
2. AbuseIPDB(可选,系统设置填写 API Key):单 IP 信誉查询,
   abuseConfidenceScore >= 阈值(默认 50)判定为恶意

设计要点:
- 所有查询结果缓存到 threat_intel_records,TTL 由 threat_intel_cache_hours 控制,
  避免重复消耗 API 配额
- feed 网段由定时任务定期全量刷新,匹配在本地完成,无实时外网调用
- 任何网络/解析异常只记日志并返回 None/False,绝不影响攻击捕获主流程
"""
import ipaddress
import logging
from datetime import datetime, timedelta

import requests
from flask import current_app

from .extensions import db
from .models import ThreatIntelRecord, AttackerProfile
from .settings_store import get_setting

logger = logging.getLogger('honeypot.threat_intel')

# source -> (feed URL, 中文类别标签)
FEEDS = {
    'spamhaus_drop': (
        'https://www.spamhaus.org/drop/drop.txt',
        'Spamhaus DROP 恶意网段',
    ),
    'spamhaus_edrop': (
        'https://www.spamhaus.org/drop/edrop.txt',
        'Spamhaus EDROP 扩展恶意网段',
    ),
}

ABUSEIPDB_CHECK_URL = 'https://api.abuseipdb.com/api/v2/check'
FEED_TIMEOUT = 10  # 秒,feed 下载只在后台任务执行,超时可放宽
API_TIMEOUT = 5

# feed 网段解析结果的进程内短期缓存,避免每次 IP 查询都全表加载
_feed_cache = {'expire_at': 0.0, 'networks': None}
_FEED_CACHE_TTL = 300  # 秒


def is_enabled() -> bool:
    try:
        return bool(get_setting(
            'threat_intel_enabled',
            current_app.config.get('THREAT_INTEL_ENABLED', True)))
    except Exception:
        return False


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def parse_feed_text(text: str):
    """解析 Spamhaus DROP 风格文本,返回 [(cidr, sbl_id), ...]。

    行格式:  1.10.16.0/20 ; SBL256894
    空行与以 ; 开头的注释行跳过。
    """
    entries = []
    for raw in (text or '').splitlines():
        line = raw.strip()
        if not line or line.startswith(';'):
            continue
        cidr = line.split(';', 1)[0].strip()
        note = ''
        if ';' in line:
            note = line.split(';', 1)[1].strip()
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        entries.append((cidr, note))
    return entries


def refresh_feeds() -> int:
    """下载并全量刷新开源 feed 网段。返回更新的条目总数。

    单个源失败不影响其他源;解析为空时不覆盖旧数据(防止异常响应清空情报)。
    """
    total = 0
    for source, (url, category) in FEEDS.items():
        try:
            resp = requests.get(url, timeout=FEED_TIMEOUT)
            resp.raise_for_status()
            entries = parse_feed_text(resp.text)
        except Exception as e:
            logger.warning('威胁情报 feed 下载失败 source=%s: %s', source, e)
            continue
        if not entries:
            logger.warning('feed %s 解析结果为空,跳过本次刷新', source)
            continue

        ThreatIntelRecord.query.filter_by(kind='feed', source=source).delete()
        for cidr, note in entries:
            db.session.add(ThreatIntelRecord(
                indicator=cidr, kind='feed', source=source,
                malicious=True, category=category,
                detail=(note or None)[:255],
                checked_at=datetime.utcnow(),
            ))
        db.session.commit()
        total += len(entries)
        logger.info('威胁情报 feed 已刷新 source=%s entries=%s', source, len(entries))

    _feed_cache['expire_at'] = 0  # 强制下次查询重新加载
    return total


def _load_feed_networks():
    """加载 feed 网段为 (network, record) 列表(带 5 分钟进程内缓存)。"""
    import time
    now = time.time()
    if _feed_cache['networks'] is not None and now < _feed_cache['expire_at']:
        return _feed_cache['networks']

    networks = []
    rows = ThreatIntelRecord.query.filter_by(kind='feed', malicious=True).all()
    for row in rows:
        try:
            networks.append((ipaddress.ip_network(row.indicator, strict=False), row))
        except ValueError:
            continue
    _feed_cache['networks'] = networks
    _feed_cache['expire_at'] = now + _FEED_CACHE_TTL
    return networks


def _match_feeds(ip: str):
    """命中开源 feed 网段则返回对应 ThreatIntelRecord,否则 None。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for network, row in _load_feed_networks():
        if addr in network:
            return row
    return None


def _query_abuseipdb(ip: str):
    """调用 AbuseIPDB 单 IP 查询。返回 (confidence, category, detail) 或 None。

    未配置 Key、网络失败或额度不足均返回 None(交给上层按非恶意处理或跳过)。
    """
    api_key = (get_setting('abuseipdb_api_key', '') or '').strip()
    if not api_key:
        return None
    try:
        resp = requests.get(
            ABUSEIPDB_CHECK_URL,
            headers={'Accept': 'application/json', 'Key': api_key},
            params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''},
            timeout=API_TIMEOUT,
        )
        if resp.status_code == 429:
            logger.warning('AbuseIPDB 配额已用尽,稍后再试')
            return None
        resp.raise_for_status()
        data = (resp.json() or {}).get('data') or {}
    except Exception as e:
        logger.warning('AbuseIPDB 查询失败 ip=%s: %s', ip, e)
        return None

    score = int(data.get('abuseConfidenceScore') or 0)
    categories = data.get('usageType') or ''
    country = data.get('countryCode') or ''
    isp = data.get('isp') or ''
    detail = '; '.join(x for x in (categories, isp, country) if x)[:255]
    return score, 'AbuseIPDB 威胁评分', detail


def _get_cached(ip: str):
    """取未过期的 IP 查询缓存(恶意/非恶意都会缓存)。"""
    ttl_hours = int(get_setting('threat_intel_cache_hours', 24) or 24)
    row = (ThreatIntelRecord.query
           .filter_by(indicator=ip, kind='ip')
           .order_by(ThreatIntelRecord.checked_at.desc())
           .first())
    if row and row.checked_at >= datetime.utcnow() - timedelta(hours=ttl_hours):
        return row
    return None


def _upsert_ip_record(ip: str, malicious: bool, source: str,
                      category=None, confidence=None, detail=None):
    row = ThreatIntelRecord.query.filter_by(
        indicator=ip, kind='ip', source=source).first()
    if row is None:
        row = ThreatIntelRecord(indicator=ip, kind='ip', source=source)
        db.session.add(row)
    row.malicious = malicious
    row.category = category
    row.confidence = confidence
    row.detail = (detail or None)
    row.checked_at = datetime.utcnow()
    db.session.commit()
    return row


def lookup_ip(ip: str, force: bool = False):
    """查询单个 IP 的威胁情报并写入缓存。

    返回 ThreatIntelRecord;情报功能关闭/内网地址/外部查询全部不可用时:
    - feed 未命中且无 API Key:缓存一条非恶意记录(source=local_feed)并返回
    - 功能关闭或内网地址:返回 None,不写缓存
    """
    if not ip or not _is_public(ip) or not is_enabled():
        return None
    if not force:
        cached = _get_cached(ip)
        if cached is not None:
            return cached

    # 1) 本地开源 feed 网段匹配
    feed_hit = _match_feeds(ip)
    if feed_hit is not None:
        return _upsert_ip_record(
            ip, True, source=feed_hit.source,
            category=feed_hit.category,
            detail=f'命中 {feed_hit.indicator}' + (f' ({feed_hit.detail})' if feed_hit.detail else ''))

    # 2) AbuseIPDB(可选)
    result = _query_abuseipdb(ip)
    if result is not None:
        score, category, detail = result
        threshold = int(get_setting('abuseipdb_threshold', 50) or 50)
        malicious = score >= threshold
        return _upsert_ip_record(
            ip, malicious, source='abuseipdb',
            category=category if malicious else None,
            confidence=score, detail=detail)

    # 3) 无可用外部源:以本地 feed 结果为准缓存,避免重复扫描
    return _upsert_ip_record(
        ip, False, source='local_feed', category=None, detail='本地 feed 未命中')


def get_ip_record(ip: str):
    """只读获取 IP 当前最新的情报记录(不触发外部查询)。"""
    return (ThreatIntelRecord.query
            .filter_by(indicator=ip, kind='ip')
            .order_by(ThreatIntelRecord.checked_at.desc())
            .first())


def malicious_attacker_count() -> int:
    """统计命中过恶意情报的攻击者画像数量(仪表盘占比用)。"""
    bad_ips = {r[0] for r in db.session.query(
        ThreatIntelRecord.indicator).filter_by(
        kind='ip', malicious=True).all()}
    if not bad_ips:
        return 0
    return (db.session.query(AttackerProfile.id)
            .filter(AttackerProfile.ip_address.in_(bad_ips))
            .count())


def backfill_uncached(limit: int = 200) -> int:
    """为尚无情报缓存的攻击者 IP 补查(定时任务调用)。返回处理条数。"""
    if not is_enabled():
        return 0
    cached = {r[0] for r in db.session.query(
        ThreatIntelRecord.indicator).filter_by(kind='ip').all()}
    q = db.session.query(AttackerProfile.ip_address).distinct()
    processed = 0
    for (ip,) in q.all():
        if ip in cached:
            continue
        try:
            lookup_ip(ip)
        except Exception:
            logger.debug('backfill 查询异常 ip=%s', ip, exc_info=True)
        processed += 1
        if processed >= limit:
            break
    logger.info('威胁情报批量补查完成 processed=%s', processed)
    return processed

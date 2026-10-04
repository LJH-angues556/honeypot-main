"""GeoIP 归属地解析(基于 ip-api.com 免费 API)

设计要点:
- 仅查询公网 IP,内网/保留地址直接跳过,不浪费配额(免费版 45 次/分钟)
- 查询失败静默返回 None,绝不让 GeoIP 故障阻断攻击捕获主流程
- 超时短(默认 3 秒),避免拖慢 capture 接口
- country 存两位国家代码(如 CN/US),与 simulate_attack 的模拟数据保持一致
- 开关/超时可在 config.py 或环境变量中调整
"""
import ipaddress
import logging

import requests
from flask import current_app

logger = logging.getLogger(__name__)

# ip-api.com 免费版端点(仅 HTTP;HTTPS 需付费)
DEFAULT_API_URL = 'http://ip-api.com/json/{ip}'
# 只取需要的字段,减少响应体积
QUERY_FIELDS = 'status,message,countryCode,city,as,isp,query'


def is_public_ip(ip: str) -> bool:
    """判断是否为公网地址(非私网/回环/保留)。"""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def lookup_ip(ip: str):
    """查询 IP 归属地。

    返回 dict {'country', 'city', 'asn', 'isp'},任一字段可能为 None;
    查询不可用或失败时返回 None。
    """
    if not ip or not is_public_ip(ip):
        return None
    from .settings_store import get_setting
    if not get_setting('geoip_enabled', current_app.config.get('GEOIP_ENABLED', True)):
        return None

    url = current_app.config.get('GEOIP_API_URL', DEFAULT_API_URL).format(ip=ip)
    timeout = current_app.config.get('GEOIP_TIMEOUT', 3)
    try:
        resp = requests.get(url, params={'fields': QUERY_FIELDS}, timeout=timeout)
        data = resp.json()
    except Exception as e:
        logger.warning('GeoIP lookup failed for %s: %s', ip, e)
        return None

    if data.get('status') != 'success':
        # 常见: private range / reserved range / invalid query
        logger.info('GeoIP lookup for %s returned: %s', ip, data.get('message'))
        return None

    # asn 字段格式为 "AS15169 Google LLC",只取 ASN 编号部分存入 asn
    as_field = (data.get('as') or '').strip()
    asn = as_field.split(' ', 1)[0] if as_field else None

    return {
        'country': data.get('countryCode') or None,
        'city': data.get('city') or None,
        'asn': asn,
        'isp': data.get('isp') or None,
    }

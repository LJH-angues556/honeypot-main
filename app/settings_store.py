"""系统设置存储服务

- SystemSetting 表以 key-value 形式保存配置,值统一以字符串存储
- 读取时按 SETTING_SPECS 声明的类型(bool/int/string)转换
- 进程内缓存 60 秒:设置保存后立即清当前 worker 缓存,其他 gunicorn
  worker 最多 60 秒后收敛,兼顾性能与"改完基本立即生效"
- 数据库中没有显式值时,回退到环境变量/Config(由调用方传入)或 spec 默认值
"""
import threading
import time

from .extensions import db
from .models import SystemSetting

# key: (类型, 默认值)。新增配置项只需在此登记
SETTING_SPECS = {
    # 基础开关
    'register_enabled':       ('bool', False),
    'geoip_enabled':          ('bool', True),
    'data_retention_days':    ('int', 30),
    'api_rate_limit':         ('string', '100 per minute'),
    # 实时告警邮件
    'email_alerts_enabled':   ('bool', False),
    # SMTP
    'smtp_enabled':           ('bool', False),
    'smtp_host':              ('string', ''),
    'smtp_port':              ('int', 587),
    'smtp_username':          ('string', ''),
    'smtp_password':          ('string', ''),
    'smtp_use_tls':           ('bool', True),
    'smtp_sender':            ('string', ''),
    # 每日报告
    'daily_report_enabled':   ('bool', False),
    'daily_report_time':      ('string', '09:00'),
    # 威胁情报(任务4.3)
    'threat_intel_enabled':   ('bool', True),
    'abuseipdb_api_key':      ('string', ''),
    'abuseipdb_threshold':    ('int', 50),
    'threat_intel_cache_hours': ('int', 24),
}

_CACHE_TTL = 60
_UNSET = object()


class _TTLCache:
    def __init__(self):
        self._data = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if not item:
                return _UNSET
            value, expire_at = item
            if time.time() > expire_at:
                self._data.pop(key, None)
                return _UNSET
            return value

    def set(self, key, value):
        with self._lock:
            self._data[key] = (value, time.time() + _CACHE_TTL)

    def clear(self):
        with self._lock:
            self._data.clear()


_cache = _TTLCache()


def _cast(key, raw):
    kind = SETTING_SPECS.get(key, ('string', None))[0]
    if raw is None:
        return None
    if kind == 'bool':
        return str(raw).strip().lower() in ('1', 'true', 'yes', 'on')
    if kind == 'int':
        try:
            return int(raw)
        except (TypeError, ValueError):
            return SETTING_SPECS[key][1]
    return str(raw)


def _serialize(key, value):
    kind = SETTING_SPECS.get(key, ('string', None))[0]
    if kind == 'bool':
        return 'true' if value else 'false'
    return '' if value is None else str(value)


def get_setting(key, default=_UNSET):
    """读取一个配置。优先 DB,其次调用方传入 default,最后 spec 默认值。"""
    cached = _cache.get(key)
    if cached is not _UNSET:
        return cached

    row = db.session.get(SystemSetting, key)
    if row is not None:
        value = _cast(key, row.value)
    elif default is not _UNSET:
        value = default
    else:
        value = SETTING_SPECS.get(key, ('string', None))[1]

    _cache.set(key, value)
    return value


def set_setting(key, value):
    """写入/更新一个配置并刷新缓存。未登记的 key 直接拒绝,防止脏配置。"""
    if key not in SETTING_SPECS:
        raise KeyError(f'Unknown setting key: {key}')
    serialized = _serialize(key, value)
    row = db.session.get(SystemSetting, key)
    if row is None:
        row = SystemSetting(key=key)
        db.session.add(row)
    row.value = serialized
    db.session.commit()
    _cache.set(key, _cast(key, serialized))


def all_settings():
    """返回全部配置的当前值 dict(供设置页渲染)。"""
    return {key: get_setting(key) for key in SETTING_SPECS}


def clear_cache():
    _cache.clear()

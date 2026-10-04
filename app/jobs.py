"""RQ 异步任务定义与轻量定时调度器

Worker 入口:  rq worker honeypot --url redis://redis:6379/0
调度器入口:  python -m app.jobs scheduler

任务函数同时兼容两种运行方式:
- worker 进程(无 Flask 上下文):自行 create_app() 建立上下文
- Web 进程内同步降级执行:复用当前 app,避免 SQLite 测试库等场景下跨 app 不可见
"""
import sys
import time
import logging
from datetime import datetime

from flask import current_app

from app import create_app
from app.extensions import db
from app.models import AttackEvent
from app.geoip import lookup_ip
from app import email_utils, tasks
from app.settings_store import get_setting

log = logging.getLogger('honeypot.jobs')

CLEANUP_TIME = '03:30'  # UTC,每天数据清理时刻
SCHEDULER_INTERVAL = 60  # 秒
THREAT_FEED_INTERVAL_HOURS = 6  # 威胁情报 feed 刷新间隔


def _has_app_context():
    try:
        current_app._get_current_object()
        return True
    except RuntimeError:
        return False


# ---------------- 异步任务(可直接被 q.enqueue) ----------------

def enrich_geoip(event_id):
    """补全攻击事件对应攻击者画像的 GeoIP 信息(已有 country 则跳过)。"""
    if _has_app_context():
        _do_enrich_geoip(event_id)
    else:
        app = create_app()
        with app.app_context():
            _do_enrich_geoip(event_id)


def _do_enrich_geoip(event_id):
    event = db.session.get(AttackEvent, event_id)
    if event is None:
        log.warning('enrich_geoip: 事件不存在 event_id=%s', event_id)
        return
    profile = event.attacker
    if not profile or profile.country:
        return
    info = lookup_ip(event.ip_address)
    if not info:
        return
    profile.country = info['country']
    profile.city = info['city']
    profile.asn = info['asn']
    profile.isp = info['isp']
    db.session.commit()
    log.info('GeoIP 补全完成 event_id=%s ip=%s country=%s',
             event_id, event.ip_address, info.get('country'))


def send_attack_alert(event_id):
    """发送高危攻击实时告警邮件。"""
    if _has_app_context():
        _do_send_attack_alert(event_id)
    else:
        app = create_app()
        with app.app_context():
            _do_send_attack_alert(event_id)


def _do_send_attack_alert(event_id):
    event = db.session.get(AttackEvent, event_id)
    if event is None:
        log.warning('send_attack_alert: 事件不存在 event_id=%s', event_id)
        return
    email_utils.send_attack_alert(event)


def evaluate_alert_rules(event_id):
    """评估所有启用的告警规则,触发时写历史并发邮件。"""
    from app.alert_engine import evaluate_alert_rules as _eval
    if _has_app_context():
        _eval(event_id)
    else:
        app = create_app()
        with app.app_context():
            _eval(event_id)


def lookup_threat(ip):
    """查询单个 IP 的威胁情报(任务4.3)。失败静默,不影响主流程。"""
    if _has_app_context():
        _do_lookup_threat(ip)
    else:
        app = create_app()
        with app.app_context():
            _do_lookup_threat(ip)


def _do_lookup_threat(ip):
    from app import threat_intel
    try:
        threat_intel.lookup_ip(ip)
    except Exception:
        log.warning('威胁情报查询失败 ip=%s', ip, exc_info=True)


def refresh_threat_feeds():
    """定时全量刷新开源威胁情报 feed。"""
    if _has_app_context():
        _do_refresh_threat_feeds()
    else:
        app = create_app()
        with app.app_context():
            _do_refresh_threat_feeds()


def _do_refresh_threat_feeds():
    from app import threat_intel
    if not threat_intel.is_enabled():
        log.info('威胁情报未启用,跳过 feed 刷新')
        return
    total = threat_intel.refresh_feeds()
    if total:
        threat_intel.backfill_uncached(limit=300)


# ---------------- 定时调度器(单容器实例运行) ----------------

def run_scheduler():
    """每分钟检查一次,到点把定时任务入队。

    - 每日报告:系统设置 daily_report_time(UTC),daily_report_enabled 开启时
    - 数据清理:每天 CLEANUP_TIME,保留天数取 data_retention_days
    - 威胁情报 feed:每 THREAT_FEED_INTERVAL 小时刷新一次(任务4.3)
    """
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [scheduler] %(levelname)s %(message)s')
    app = create_app()
    last_report_day = None
    last_cleanup_day = None
    last_feed_hour = -1
    log.info('定时调度器已启动')
    while True:
        try:
            with app.app_context():
                now = datetime.utcnow()
                today = now.date()
                hhmm = now.strftime('%H:%M')
                queue = getattr(app, 'task_queue', None)

                report_time = get_setting('daily_report_time', '09:00')
                if (get_setting('daily_report_enabled', False)
                        and hhmm == report_time and last_report_day != today):
                    if queue is not None:
                        queue.enqueue(tasks.generate_daily_report)
                        log.info('已入队每日报告任务')
                    else:
                        tasks.generate_daily_report()
                    last_report_day = today

                if hhmm == CLEANUP_TIME and last_cleanup_day != today:
                    if queue is not None:
                        queue.enqueue(tasks.cleanup_old_data)
                        log.info('已入队数据清理任务')
                    else:
                        tasks.cleanup_old_data()
                    last_cleanup_day = today

                # 威胁情报:每 6 小时刷新一次开源 feed 并补查未缓存 IP
                if now.hour % THREAT_FEED_INTERVAL_HOURS == 0 \
                        and last_feed_hour != now.hour:
                    if queue is not None:
                        queue.enqueue(refresh_threat_feeds)
                    else:
                        refresh_threat_feeds()
                    last_feed_hour = now.hour
        except Exception:
            log.exception('调度器本轮检查异常')
        time.sleep(SCHEDULER_INTERVAL)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'scheduler':
        run_scheduler()
    else:
        print('用法: python -m app.jobs scheduler')

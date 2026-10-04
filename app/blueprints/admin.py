from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response, Response, abort
from flask_login import login_required, current_user  # pyright: ignore[reportMissingImports]

from ..decorators import admin_required, super_admin_required
from ..extensions import db
from ..models import AttackEvent, AttackerProfile, HoneypotNode, AlertRule, AlertHistory, AuditLog, User
from ..models import ROLES, ROLE_LABELS, ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_VIEWER
from datetime import datetime, timedelta
import secrets
import random


admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/stream')
@login_required
def stream():
    """SSE 实时事件流:登录用户建立长连接,接收新攻击事件推送。

    EventSource 随同源请求自动携带 session cookie;Redis 不可用时返回 503,
    前端浏览器会自动退避重连。
    """
    import redis as _redis
    from .. import realtime
    try:
        pubsub = realtime.subscribe()
    except _redis.RedisError:
        abort(503)

    resp = Response(realtime.generate(pubsub), mimetype='text/event-stream')
    resp.headers['Cache-Control'] = 'no-cache'
    resp.headers['X-Accel-Buffering'] = 'no'  # 禁用 nginx 缓冲,即时下发
    resp.headers['Connection'] = 'keep-alive'
    return resp


@admin_bp.route('/dashboard')
@login_required
def dashboard():
    total_attacks = AttackEvent.query.count()
    unique_attackers = AttackerProfile.query.count()
    recent_attacks = AttackEvent.query.order_by(AttackEvent.timestamp.desc()).limit(20).all()

    # 已知威胁 IP 统计(任务4.3)
    from .. import threat_intel
    malicious_attackers = threat_intel.malicious_attacker_count()
    threat_ratio = round(malicious_attackers * 100 / unique_attackers, 1) \
        if unique_attackers else 0

    # 获取攻击类型统计(转成普通二元组列表,模板循环与 tojson 都可直接用)
    attack_types = [
        (row[0], row[1]) for row in db.session.query(
            AttackEvent.honeypot_service,
            db.func.count(AttackEvent.id).label('count')
        ).group_by(AttackEvent.honeypot_service).all()
    ]

    # 获取地区统计
    country_stats = [
        (row[0], row[1]) for row in db.session.query(
            AttackerProfile.country,
            db.func.count(AttackEvent.id).label('count')
        ).join(AttackEvent, AttackerProfile.id == AttackEvent.attacker_id)
        .group_by(AttackerProfile.country).all()
    ]

    # 获取严重级别统计
    severity_stats = [
        (row[0], row[1]) for row in db.session.query(
            AttackEvent.severity,
            db.func.count(AttackEvent.id).label('count')
        ).group_by(AttackEvent.severity).all()
    ]
    
    # 获取最新更新时间
    latest_update = AttackEvent.query.order_by(AttackEvent.timestamp.desc()).first()
    
    return render_template('dashboard.html', 
                         total_attacks=total_attacks, 
                         unique_attackers=unique_attackers, 
                         recent_attacks=recent_attacks,
                         attack_types=attack_types,
                         country_stats=country_stats,
                         severity_stats=severity_stats,
                         malicious_attackers=malicious_attackers,
                         threat_ratio=threat_ratio,
                         latest_update=latest_update)


@admin_bp.route('/attackers')
@login_required
def attackers():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=20, type=int)
    filters = {k: (request.args.get(k) or '') for k in
               ('ip', 'country', 'is_blocked', 'min_count', 'max_count',
                'first_seen_from', 'last_seen_to')}

    query = AttackerProfile.query
    if filters['ip']:
        query = query.filter(AttackerProfile.ip_address.contains(filters['ip']))
    if filters['country']:
        query = query.filter(AttackerProfile.country == filters['country'])
    if filters['is_blocked'] in ('1', 'true', 'yes'):
        query = query.filter(AttackerProfile.is_blocked.is_(True))
    elif filters['is_blocked'] in ('0', 'false', 'no'):
        query = query.filter(AttackerProfile.is_blocked.is_(False))
    # 攻击次数范围:用子查询聚合
    if filters['min_count'] or filters['max_count']:
        subq = db.session.query(
            AttackEvent.attacker_id.label('pid'),
            db.func.count(AttackEvent.id).label('cnt'),
        ).group_by(AttackEvent.attacker_id).subquery()
        query = query.outerjoin(subq, subq.c.pid == AttackerProfile.id)
        try:
            if filters['min_count']:
                query = query.filter(db.func.coalesce(subq.c.cnt, 0) >= int(filters['min_count']))
            if filters['max_count']:
                query = query.filter(db.func.coalesce(subq.c.cnt, 0) <= int(filters['max_count']))
        except ValueError:
            pass
    if filters['first_seen_from']:
        try:
            query = query.filter(AttackerProfile.first_seen >=
                                 datetime.strptime(filters['first_seen_from'], '%Y-%m-%d'))
        except ValueError:
            pass
    if filters['last_seen_to']:
        try:
            end_dt = datetime.strptime(filters['last_seen_to'], '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AttackerProfile.last_seen < end_dt)
        except ValueError:
            pass

    pagination = query.order_by(AttackerProfile.last_seen.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    # 预计算当前页画像的攻击次数
    pids = [p.id for p in pagination.items]
    counts = {}
    if pids:
        counts = dict(db.session.query(
            AttackEvent.attacker_id, db.func.count(AttackEvent.id)
        ).filter(AttackEvent.attacker_id.in_(pids))
         .group_by(AttackEvent.attacker_id).all())
    return render_template('attackers.html', profiles=pagination.items,
                           pagination=pagination, filters=filters,
                           attack_counts=counts)


@admin_bp.route('/attackers/<int:profile_id>')
@login_required
def attacker_detail(profile_id):
    profile = AttackerProfile.query.get_or_404(profile_id)
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=20, type=int)
    pagination = AttackEvent.query.filter_by(attacker_id=profile_id) \
        .order_by(AttackEvent.timestamp.desc()) \
        .paginate(page=page, per_page=per_page, error_out=False)
    from .. import threat_intel
    threat = threat_intel.get_ip_record(profile.ip_address)
    return render_template('attacker_detail.html', profile=profile,
                           events=pagination.items, pagination=pagination,
                           threat=threat)


def _redirect_back(fallback_endpoint, **kwargs):
    """安全地重定向回来源页:仅允许同源 referrer,防止开放重定向。"""
    from urllib.parse import urlparse
    ref = request.referrer or ''
    parsed = urlparse(ref)
    if ref and (not parsed.netloc or parsed.netloc == request.host):
        return redirect(ref)
    return redirect(url_for(fallback_endpoint, **kwargs))


@admin_bp.route('/attackers/<int:profile_id>/block', methods=['POST'])
@login_required
@admin_required
def block_attacker(profile_id):
    profile = AttackerProfile.query.get_or_404(profile_id)
    profile.is_blocked = True
    reason = (request.form.get('block_reason') or '').strip()
    profile.block_reason = reason or None
    profile.blocked_at = datetime.utcnow()
    db.session.commit()
    from ..audit import audit
    audit('block_ip', f'封禁 IP {profile.ip_address} 原因:{reason or "(未填写)"}')
    flash(f'已封禁 IP：{profile.ip_address}', 'success')
    return _redirect_back('admin.attacker_detail', profile_id=profile.id)


@admin_bp.route('/attackers/<int:profile_id>/unblock', methods=['POST'])
@login_required
@admin_required
def unblock_attacker(profile_id):
    profile = AttackerProfile.query.get_or_404(profile_id)
    profile.is_blocked = False
    profile.block_reason = None
    profile.blocked_at = None
    db.session.commit()
    from ..audit import audit
    audit('unblock_ip', f'解封 IP {profile.ip_address}')
    flash(f'已解封 IP：{profile.ip_address}', 'success')
    return _redirect_back('admin.attacker_detail', profile_id=profile.id)


@admin_bp.route('/blacklist/unblock', methods=['POST'])
@login_required
@admin_required
def blacklist_unblock_batch():
    """批量解封:表单字段 ids 为 profile id 列表"""
    ids = request.form.getlist('ids')
    if ids:
        count = AttackerProfile.query.filter(
            AttackerProfile.id.in_(ids), AttackerProfile.is_blocked.is_(True)
        ).update({
            AttackerProfile.is_blocked: False,
            AttackerProfile.block_reason: None,
            AttackerProfile.blocked_at: None,
        }, synchronize_session=False)
        db.session.commit()
        flash(f'已批量解封 {count} 个 IP', 'success')
    else:
        flash('未选择任何 IP', 'error')
    return redirect(url_for('admin.blacklist'))


@admin_bp.route('/blacklist')
@login_required
def blacklist():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=20, type=int)
    ip = request.args.get('ip')

    query = AttackerProfile.query.filter_by(is_blocked=True)
    if ip:
        query = query.filter(AttackerProfile.ip_address.contains(ip))
    pagination = query.order_by(AttackerProfile.blocked_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template('blacklist.html', profiles=pagination.items,
                           pagination=pagination, ip=ip or '')


@admin_bp.route('/blacklist/export')
@login_required
def export_blacklist():
    """导出黑名单:txt(每行一个 IP,可直接喂给 iptables)或 csv(含原因/时间)"""
    import csv
    import io

    fmt = (request.args.get('format') or 'txt').lower()
    profiles = (AttackerProfile.query.filter_by(is_blocked=True)
                .order_by(AttackerProfile.blocked_at.desc()).all())
    stamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')

    if fmt == 'csv':
        buf = io.StringIO()
        buf.write('﻿')  # UTF-8 BOM,让 Excel 正确识别中文
        writer = csv.writer(buf)
        writer.writerow(['ip_address', 'block_reason', 'blocked_at_utc'])
        for p in profiles:
            writer.writerow([
                p.ip_address,
                p.block_reason or '',
                p.blocked_at.strftime('%Y-%m-%d %H:%M:%S') if p.blocked_at else '',
            ])
        resp = make_response(buf.getvalue())
        resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
        resp.headers['Content-Disposition'] = f'attachment; filename=blacklist-{stamp}.csv'
        return resp

    # 默认 txt:每行一个 IP,可直接用于 `while read ip; do iptables -A ...; done`
    content = '\n'.join(p.ip_address for p in profiles)
    resp = make_response(content + ('\n' if content else ''))
    resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
    resp.headers['Content-Disposition'] = f'attachment; filename=blacklist-{stamp}.txt'
    return resp


@admin_bp.route('/attacks')
@login_required
def attacks():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=20, type=int)
    filters = {k: (request.args.get(k) or '') for k in
               ('ip', 'method', 'severity', 'service', 'signature',
                'start_date', 'end_date', 'country')}
    query = _apply_attack_filters(AttackEvent.query, filters)

    pagination = query.order_by(AttackEvent.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)

    # 批量查出当前页中已被封禁的攻击者 id,供列表行高亮(避免 N+1)
    attacker_ids = {e.attacker_id for e in pagination.items if e.attacker_id}
    blocked_attacker_ids = set()
    if attacker_ids:
        blocked_attacker_ids = {
            row[0] for row in db.session.query(AttackerProfile.id)
            .filter(AttackerProfile.id.in_(attacker_ids),
                    AttackerProfile.is_blocked.is_(True)).all()
        }

    return render_template('attacks.html', events=pagination.items, pagination=pagination,
                           filters=filters,
                           blocked_attacker_ids=blocked_attacker_ids)


@admin_bp.route('/attacks/export')
@login_required
def export_attacks():
    """导出攻击事件:csv/json/xlsx,复用列表筛选条件;超大数据量异步邮件发送。"""
    from .. import export_utils
    from ..async_utils import enqueue

    fmt = (request.args.get('format') or 'csv').lower()
    if fmt not in ('csv', 'json', 'xlsx'):
        fmt = 'csv'

    filters = {k: (request.args.get(k) or '') for k in
               ('ip', 'method', 'severity', 'service', 'signature',
                'start_date', 'end_date', 'country')}
    query = _apply_attack_filters(AttackEvent.query, filters)

    total = query.count()
    from ..audit import audit
    audit('export_attacks', f'导出攻击事件 format={fmt} total={total}')

    # 大数据量:异步生成 CSV 并邮件发送给当前用户(避免长请求)
    if total > export_utils.ASYNC_THRESHOLD:
        recipient = getattr(current_user, 'email', None)
        if recipient:
            enqueue(_export_attacks_email_job, filters, recipient)
            flash(f'共 {total} 条数据,导出完成后将发送 CSV 到 {recipient}', 'success')
            return redirect(url_for('admin.attacks', **filters))
        flash(f'共 {total} 条数据,因未配置邮箱改为同步导出(可能较慢)', 'warning')

    events = query.order_by(AttackEvent.timestamp.desc()).all()
    stamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    if fmt == 'json':
        body = export_utils.events_json(events)
        resp = make_response(body)
        resp.headers['Content-Type'] = 'application/json; charset=utf-8'
        resp.headers['Content-Disposition'] = f'attachment; filename=attacks-{stamp}.json'
    elif fmt == 'xlsx':
        body = export_utils.events_xlsx(events)
        resp = make_response(body)
        resp.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        resp.headers['Content-Disposition'] = f'attachment; filename=attacks-{stamp}.xlsx'
    else:
        body = export_utils.events_csv(events)
        resp = make_response(body)
        resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
        resp.headers['Content-Disposition'] = f'attachment; filename=attacks-{stamp}.csv'
    return resp


def _apply_attack_filters(query, filters):
    """攻击事件列表与导出共用的筛选逻辑。"""
    if filters.get('ip'):
        query = query.filter(AttackEvent.ip_address.contains(filters['ip']))
    if filters.get('method'):
        query = query.filter(AttackEvent.method == filters['method'])
    if filters.get('severity'):
        query = query.filter(AttackEvent.severity == filters['severity'])
    if filters.get('service'):
        query = query.filter(AttackEvent.honeypot_service == filters['service'])
    if filters.get('signature'):
        query = query.filter(AttackEvent.signature.contains(filters['signature']))
    if filters.get('start_date'):
        try:
            query = query.filter(AttackEvent.timestamp >=
                                 datetime.strptime(filters['start_date'], '%Y-%m-%d'))
        except ValueError:
            pass
    if filters.get('end_date'):
        try:
            end_dt = datetime.strptime(filters['end_date'], '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AttackEvent.timestamp < end_dt)
        except ValueError:
            pass
    if filters.get('country'):
        query = query.join(AttackerProfile, AttackEvent.attacker_id == AttackerProfile.id)\
                     .filter(AttackerProfile.country == filters['country'])
    return query


def _export_attacks_email_job(filters, recipient):
    """RQ job:生成攻击事件 CSV 并邮件发送。"""
    from app import create_app
    from app.extensions import db
    from app.models import AttackEvent
    from app.email_utils import send_email
    from app import export_utils as eu

    app = create_app()
    with app.app_context():
        query = _apply_attack_filters(AttackEvent.query, filters)
        events = query.order_by(AttackEvent.timestamp.desc()).all()
        csv_text = eu.events_csv(events)
        stamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        send_email(
            recipient,
            f'【蜜罐导出】攻击事件共 {len(events)} 条',
            f'<p>您请求的攻击事件导出已完成,共 {len(events)} 条,CSV 见附件。</p>',
            attachments=[(f'attacks-{stamp}.csv', csv_text.encode('utf-8-sig'), 'text/csv')],
        )
        db.session.remove()


@admin_bp.route('/attackers/export')
@login_required
def export_attackers():
    """导出攻击者画像:csv/json/xlsx。"""
    from .. import export_utils

    fmt = (request.args.get('format') or 'csv').lower()
    if fmt not in ('csv', 'json', 'xlsx'):
        fmt = 'csv'

    profiles = AttackerProfile.query.order_by(AttackerProfile.last_seen.desc()).all()
    # 预计算每个画像的攻击次数
    counts = dict(db.session.query(
        AttackEvent.attacker_id, db.func.count(AttackEvent.id)
    ).group_by(AttackEvent.attacker_id).all()) if profiles else {}
    rows = [(p, counts.get(p.id, 0)) for p in profiles]

    from ..audit import audit
    audit('export_attackers', f'导出攻击者画像 format={fmt} total={len(rows)}')

    stamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    if fmt == 'json':
        body = export_utils.attackers_json(rows)
        resp = make_response(body)
        resp.headers['Content-Type'] = 'application/json; charset=utf-8'
        resp.headers['Content-Disposition'] = f'attachment; filename=attackers-{stamp}.json'
    elif fmt == 'xlsx':
        body = export_utils.attackers_xlsx(rows)
        resp = make_response(body)
        resp.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        resp.headers['Content-Disposition'] = f'attachment; filename=attackers-{stamp}.xlsx'
    else:
        body = export_utils.attackers_csv(rows)
        resp = make_response(body)
        resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
        resp.headers['Content-Disposition'] = f'attachment; filename=attackers-{stamp}.csv'
    return resp


@admin_bp.route('/attacks/<int:event_id>')
@login_required
def attack_detail(event_id):
    event = AttackEvent.query.get_or_404(event_id)
    return render_template('attack_detail.html', event=event)


@admin_bp.route('/stats')
@login_required
def stats():
    # 数据统计模块
    total_events = AttackEvent.query.count()
    total_attackers = AttackerProfile.query.count()
    latest_event = AttackEvent.query.order_by(AttackEvent.timestamp.desc()).first()

    # 最近 7 天攻击趋势(含天数标签,无数据的天补 0)
    from datetime import timedelta
    today = datetime.utcnow().date()
    seven_days_ago = today - timedelta(days=6)
    daily_counts = (
        db.session.query(
            db.func.date(AttackEvent.timestamp).label('day'),
            db.func.count(AttackEvent.id).label('count')
        )
        .filter(AttackEvent.timestamp >= seven_days_ago)
        .group_by(db.func.date(AttackEvent.timestamp))
        .order_by('day')
        .all()
    )
    day_map = {str(row.day): row.count for row in daily_counts}
    trend_labels = [(seven_days_ago + timedelta(days=i)).strftime('%m-%d') for i in range(7)]
    trend_data = [day_map.get(str(seven_days_ago + timedelta(days=i)), 0) for i in range(7)]

    # 严重级别分布
    severity_stats = [
        (row[0], row[1]) for row in db.session.query(
            AttackEvent.severity,
            db.func.count(AttackEvent.id).label('count')
        ).group_by(AttackEvent.severity).all()
    ]

    # Top 10 攻击 IP
    top_ips = [
        (row[0], row[1]) for row in db.session.query(
            AttackEvent.ip_address,
            db.func.count(AttackEvent.id).label('count')
        )
        .group_by(AttackEvent.ip_address)
        .order_by(db.desc('count'))
        .limit(10)
        .all()
    ]

    return render_template('stats.html',
                           total_events=total_events,
                           total_attackers=total_attackers,
                           latest_event=latest_event,
                           trend_labels=trend_labels,
                           trend_data=trend_data,
                           severity_stats=severity_stats,
                           top_ips=top_ips)


@admin_bp.route('/database')
@login_required
def database():
    # 数据库页面：展示各表与行数
    tables = []
    try:
        # 获取表名
        result = db.session.execute(db.text('SHOW TABLES'))
        table_names = [row[0] for row in result]
        for name in table_names:
            try:
                count = db.session.execute(db.text(f'SELECT COUNT(*) FROM `{name}`')).scalar() or 0
            except Exception:
                count = 'N/A'
            tables.append({'name': name, 'rows': count})
    except Exception as e:
        tables = []
        flash(f'读取数据库结构失败: {e}', 'error')
    return render_template('database.html', tables=tables)


@admin_bp.route('/map')
@login_required
def map():
    # 获取攻击数据用于地图显示
    rows = (
        db.session.query(
            AttackerProfile.country,
            db.func.count(AttackEvent.id).label('count')
        )
        .join(AttackEvent, AttackerProfile.id == AttackEvent.attacker_id)
        .group_by(AttackerProfile.country)
        .all()
    )
    attacks_by_country = [{'country': r[0] or 'Unknown', 'count': int(r[1] or 0)} for r in rows]

    return render_template('map.html', attacks_by_country=attacks_by_country)


@admin_bp.route('/simulate-attack', methods=['POST'])
@login_required
@admin_required
def simulate_attack():
    """生成模拟攻击数据(任务4.5:支持自定义参数与批量生成)。

    表单字段(均可选,留空随机):ip/user_agent/country/severity/
    honeypot_service/signature;count 为批量条数(1-100,默认 1)。
    """
    COUNTRIES = ['CN', 'US', 'RU', 'IN', 'DE', 'FR', 'GB', 'BR', 'JP', 'KR']
    SEVERITIES = ['low', 'medium', 'high']
    SERVICES = ['web', 'ssh', 'telnet', 'redis']
    SIGNATURES = ['sql_injection', 'xss_attempt', 'brute_force',
                  'directory_scan', 'unauth_access', 'sim-test']
    PATHS = {
        'web': '/admin/login', 'ssh': '/ssh/auth',
        'telnet': '/telnet/login', 'redis': '/redis/cmd',
    }

    try:
        count = max(1, min(100, int(request.form.get('count') or 1)))
    except ValueError:
        count = 1

    f_ip = (request.form.get('ip') or '').strip()
    f_ua = (request.form.get('user_agent') or request.form.get('ua') or '').strip()
    f_country = (request.form.get('country') or '').strip()
    f_severity = (request.form.get('severity') or '').strip()
    f_service = (request.form.get('honeypot_service') or '').strip()
    f_signature = (request.form.get('signature') or '').strip()

    if f_severity and f_severity not in SEVERITIES:
        f_severity = ''

    last_event = None
    for _ in range(count):
        # 批量模式下 IP 逐条随机;单条且指定 IP 时使用指定值
        ip = f_ip if (count == 1 and f_ip) else \
            (f_ip if f_ip and random.random() < 0.3
             else f"192.168.{random.randint(0,255)}.{random.randint(1,254)}")
        ua = f_ua or 'Mozilla/5.0 (Simulation)'
        country = f_country or random.choice(COUNTRIES)
        severity = f_severity or random.choice(SEVERITIES)
        service = f_service or random.choice(SERVICES)
        signature = f_signature or random.choice(SIGNATURES)

        profile = AttackerProfile.query.filter_by(ip_address=ip).first()
        if not profile:
            profile = AttackerProfile(
                ip_address=ip, user_agent=ua, country=country, city='',
                first_seen=datetime.utcnow(), last_seen=datetime.utcnow())
            db.session.add(profile)
        else:
            profile.last_seen = datetime.utcnow()
            if f_ua:
                profile.user_agent = f_ua
            profile.country = country or profile.country

        event = AttackEvent(
            ip_address=ip,
            method='GET',
            path=PATHS.get(service, '/honeypot'),
            headers={'User-Agent': ua},
            payload={'simulated': True},
            honeypot_service=service,
            signature=signature,
            severity=severity,
            attacker=profile,
        )
        db.session.add(event)
        last_event = event
    db.session.commit()

    # 实时推送到在线仪表盘(批量时只推最后一条,payload 中总量已更新)
    if last_event is not None:
        try:
            from ..realtime import publish_event, build_event_payload
            publish_event(build_event_payload(last_event))
        except Exception:
            pass

    flash(f'已生成 {count} 条模拟攻击数据', 'success')
    return redirect(url_for('admin.attacks'))


@admin_bp.route('/export-stats')
@login_required
def export_stats():
    # 导出简要统计为txt
    total_events = AttackEvent.query.count()
    total_attackers = AttackerProfile.query.count()
    by_country = (
        db.session.query(AttackerProfile.country, db.func.count(AttackEvent.id))
        .join(AttackEvent, AttackerProfile.id == AttackEvent.attacker_id)
        .group_by(AttackerProfile.country)
        .all()
    )
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    lines = [
        f"Export Time: {now}",
        f"Total Events: {total_events}",
        f"Total Attackers: {total_attackers}",
        "By Country:",
    ]
    for c, cnt in by_country:
        lines.append(f"  {c or 'Unknown'}: {cnt}")
    content = "\n".join(lines)
    resp = make_response(content)
    filename = datetime.utcnow().strftime('stats-%Y%m%d-%H%M%S.txt')
    resp.headers['Content-Type'] = 'text/plain; charset=utf-8'
    resp.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return resp

# 个人设置页(所有登录用户可访问,系统设置在 settings 蓝图中限超管)
@admin_bp.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


# ---------------- 蜜罐节点管理(任务2.2) ----------------

@admin_bp.route('/nodes')
@login_required
def nodes():
    all_nodes = HoneypotNode.query.order_by(HoneypotNode.created_at.desc()).all()
    online_count = sum(1 for n in all_nodes if n.is_online)
    return render_template(
        'nodes.html', nodes=all_nodes,
        online_count=online_count, total_nodes=len(all_nodes),
    )


@admin_bp.route('/nodes/create', methods=['POST'])
@login_required
@super_admin_required
def create_node():
    name = (request.form.get('name') or '').strip()[:64]
    service_type = (request.form.get('service_type') or 'http').strip()[:32] or 'http'
    if not name:
        flash('节点名称不能为空', 'error')
        return redirect(url_for('admin.nodes'))
    if HoneypotNode.query.filter_by(name=name).first():
        flash(f'节点名称 {name} 已存在', 'error')
        return redirect(url_for('admin.nodes'))

    node = HoneypotNode(
        name=name,
        node_key=secrets.token_hex(32),
        service_type=service_type,
        status='offline',
    )
    db.session.add(node)
    db.session.commit()
    # node_key 仅此完整展示一次,列表页只展示脱敏形式
    flash(f'节点 {name} 创建成功,请立即保存节点密钥(仅显示一次):{node.node_key}', 'success')
    return redirect(url_for('admin.nodes'))


@admin_bp.route('/nodes/<int:node_id>/delete', methods=['POST'])
@login_required
@super_admin_required
def delete_node(node_id):
    node = HoneypotNode.query.get_or_404(node_id)
    name = node.name
    db.session.delete(node)
    db.session.commit()
    flash(f'节点 {name} 已删除(其历史攻击事件保留,节点关联已解除)', 'success')
    return redirect(url_for('admin.nodes'))


# ---------------- 告警规则引擎(任务3.4) ----------------

RULE_TYPES = {
    'high_severity': '高危攻击',
    'ip_frequency': 'IP 频率',
    'new_attacker': '新攻击者',
    'new_country': '新国家/地区',
}


@admin_bp.route('/alerts')
@login_required
def alert_rules():
    rules = AlertRule.query.order_by(AlertRule.enabled.desc(), AlertRule.id.desc()).all()
    recent = AlertHistory.query.order_by(AlertHistory.created_at.desc()).limit(20).all()
    return render_template(
        'alert_rules.html', rules=rules, recent=recent,
        rule_types=RULE_TYPES,
    )


@admin_bp.route('/alerts/create', methods=['POST'])
@login_required
@admin_required
def create_alert_rule():
    name = (request.form.get('name') or '').strip()[:128]
    rule_type = (request.form.get('rule_type') or '').strip()
    if not name or rule_type not in RULE_TYPES:
        flash('规则名称与类型不能为空', 'error')
        return redirect(url_for('admin.alert_rules'))
    rule = AlertRule(
        name=name,
        rule_type=rule_type,
        severity=(request.form.get('severity') or None) or None,
        signature=(request.form.get('signature') or '').strip()[:128] or None,
        threshold=_int_or_none(request.form.get('threshold')),
        window_minutes=_int_or_none(request.form.get('window_minutes')) or 5,
        cooldown_minutes=_int_or_none(request.form.get('cooldown_minutes')) or 60,
        enabled=request.form.get('enabled') is not None,
    )
    db.session.add(rule)
    db.session.commit()
    from ..audit import audit
    audit('create_alert_rule', f'创建告警规则「{name}」类型={rule_type}')
    flash(f'告警规则「{name}」已创建', 'success')
    return redirect(url_for('admin.alert_rules'))


def _int_or_none(value):
    try:
        return int(value) if value not in (None, '') else None
    except (TypeError, ValueError):
        return None


@admin_bp.route('/alerts/<int:rule_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_alert_rule(rule_id):
    rule = AlertRule.query.get_or_404(rule_id)
    rule.enabled = not rule.enabled
    db.session.commit()
    from ..audit import audit
    audit('toggle_alert_rule', f'规则「{rule.name}」{"启用" if rule.enabled else "禁用"}')
    flash(f'规则「{rule.name}」已{"启用" if rule.enabled else "禁用"}', 'success')
    return redirect(url_for('admin.alert_rules'))


@admin_bp.route('/alerts/<int:rule_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_alert_rule(rule_id):
    rule = AlertRule.query.get_or_404(rule_id)
    name = rule.name
    db.session.delete(rule)
    db.session.commit()
    from ..audit import audit
    audit('delete_alert_rule', f'删除告警规则「{name}」')
    flash(f'规则「{name}」已删除', 'success')
    return redirect(url_for('admin.alert_rules'))


@admin_bp.route('/alert-history')
@login_required
def alert_history():
    page = request.args.get('page', 1, type=int)
    query = AlertHistory.query.order_by(AlertHistory.created_at.desc())
    pagination = query.paginate(page=page, per_page=30, error_out=False)
    return render_template('alert_history.html', pagination=pagination,
                           rule_types=RULE_TYPES)


# ---------------- 操作审计日志(任务3.5) ----------------

@admin_bp.route('/audit-logs')
@login_required
def audit_logs():
    page = request.args.get('page', 1, type=int)
    action = request.args.get('action', '').strip()
    query = AuditLog.query.order_by(AuditLog.created_at.desc())
    if action:
        query = query.filter(AuditLog.action == action)
    pagination = query.paginate(page=page, per_page=30, error_out=False)
    actions = [row[0] for row in db.session.query(AuditLog.action).distinct().all()]
    return render_template('audit_logs.html', pagination=pagination,
                           actions=actions, current_action=action)


# ---------------- 用户权限管理(任务4.2,仅超级管理员) ----------------

def _super_admin_count():
    return User.query.filter_by(role=ROLE_SUPER_ADMIN).count()


@admin_bp.route('/users')
@login_required
@super_admin_required
def users():
    all_users = User.query.order_by(User.id.asc()).all()
    return render_template('users.html', users=all_users,
                           roles=ROLES, role_labels=ROLE_LABELS)


@admin_bp.route('/users/create', methods=['POST'])
@login_required
@super_admin_required
def create_user():
    username = (request.form.get('username') or '').strip()[:80]
    email = (request.form.get('email') or '').strip().lower()[:120] or None
    password = request.form.get('password') or ''
    role = request.form.get('role') or ROLE_VIEWER

    if not username or len(password) < 6:
        flash('用户名不能为空且密码至少 6 位', 'error')
        return redirect(url_for('admin.users'))
    if role not in ROLES:
        flash('非法角色', 'error')
        return redirect(url_for('admin.users'))
    if User.query.filter_by(username=username).first():
        flash(f'用户名 {username} 已存在', 'error')
        return redirect(url_for('admin.users'))
    if email and User.query.filter_by(email=email).first():
        flash('该邮箱已被使用', 'error')
        return redirect(url_for('admin.users'))

    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    from ..audit import audit
    audit('create_user', f'创建用户 {username} 角色 {ROLE_LABELS.get(role, role)}')
    flash(f'用户 {username} 创建成功', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/role', methods=['POST'])
@login_required
@super_admin_required
def change_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role') or ''
    if new_role not in ROLES:
        flash('非法角色', 'error')
        return redirect(url_for('admin.users'))
    if user.id == current_user.id and new_role != ROLE_SUPER_ADMIN:
        flash('不能降低自己的超级管理员角色', 'error')
        return redirect(url_for('admin.users'))
    # 最后一个超级管理员不能被降级
    if user.role == ROLE_SUPER_ADMIN and new_role != ROLE_SUPER_ADMIN \
            and _super_admin_count() <= 1:
        flash('系统至少保留一个超级管理员', 'error')
        return redirect(url_for('admin.users'))

    old = user.role
    user.role = new_role
    db.session.commit()
    from ..audit import audit
    audit('update_user_role', f'用户 {user.username} 角色 {old} -> {new_role}')
    flash(f'{user.username} 的角色已更新为 {ROLE_LABELS.get(new_role, new_role)}', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@super_admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('不能禁用自己的账号', 'error')
        return redirect(url_for('admin.users'))
    if user.role == ROLE_SUPER_ADMIN and user.active and _super_admin_count() <= 1:
        flash('不能禁用最后一个超级管理员', 'error')
        return redirect(url_for('admin.users'))

    user.active = not user.active
    db.session.commit()
    from ..audit import audit
    audit('toggle_user', f'用户 {user.username} {"启用" if user.active else "禁用"}')
    flash(f'用户 {user.username} 已{"启用" if user.active else "禁用"}', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@super_admin_required
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password') or ''
    if len(new_password) < 6:
        flash('新密码至少 6 位', 'error')
        return redirect(url_for('admin.users'))
    user.set_password(new_password)
    db.session.commit()
    from ..audit import audit
    audit('reset_user_password', f'超级管理员重置用户 {user.username} 的密码')
    flash(f'{user.username} 的密码已重置', 'success')
    return redirect(url_for('admin.users'))
"""数据导出工具:攻击事件/攻击者画像的 CSV / JSON / Excel 生成。

大数据量(超过 ASYNC_THRESHOLD)由 RQ 异步生成并邮件发送给请求人,
避免长请求超时。
"""
import csv
import io
import json

ASYNC_THRESHOLD = 2000  # 超过此条数走异步 + 邮件

EVENT_COLUMNS = [
    'id', 'timestamp_utc', 'ip_address', 'method', 'path',
    'honeypot_service', 'signature', 'severity', 'attacker_id', 'node_id',
    'payload_json',
]
ATTACKER_COLUMNS = [
    'id', 'ip_address', 'country', 'city', 'asn', 'isp',
    'attack_count', 'first_seen_utc', 'last_seen_utc',
    'is_blocked', 'block_reason', 'blocked_at_utc',
]


def _event_row(e):
    return [
        e.id,
        e.timestamp.strftime('%Y-%m-%d %H:%M:%S') if e.timestamp else '',
        e.ip_address,
        e.method or '',
        e.path or '',
        e.honeypot_service or '',
        e.signature or '',
        e.severity or '',
        e.attacker_id or '',
        e.node_id or '',
        json.dumps(e.payload, ensure_ascii=False) if e.payload else '',
    ]


def _attacker_row(p, attack_count):
    return [
        p.id,
        p.ip_address,
        p.country or '',
        p.city or '',
        p.asn or '',
        p.isp or '',
        attack_count,
        p.first_seen.strftime('%Y-%m-%d %H:%M:%S') if p.first_seen else '',
        p.last_seen.strftime('%Y-%m-%d %H:%M:%S') if p.last_seen else '',
        int(bool(p.is_blocked)),
        p.block_reason or '',
        p.blocked_at.strftime('%Y-%m-%d %H:%M:%S') if p.blocked_at else '',
    ]


def events_csv(events):
    buf = io.StringIO()
    buf.write('﻿')  # UTF-8 BOM
    writer = csv.writer(buf)
    writer.writerow(EVENT_COLUMNS)
    for e in events:
        writer.writerow(_event_row(e))
    return buf.getvalue()


def events_json(events):
    return json.dumps([dict(zip(EVENT_COLUMNS, _event_row(e))) for e in events],
                      ensure_ascii=False, indent=2)


def events_xlsx(events):
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = 'attack_events'
    ws.append(EVENT_COLUMNS)
    for e in events:
        ws.append(_event_row(e))
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def attackers_csv(attackers_with_counts):
    buf = io.StringIO()
    buf.write('﻿')
    writer = csv.writer(buf)
    writer.writerow(ATTACKER_COLUMNS)
    for p, count in attackers_with_counts:
        writer.writerow(_attacker_row(p, count))
    return buf.getvalue()


def attackers_json(attackers_with_counts):
    return json.dumps(
        [dict(zip(ATTACKER_COLUMNS, _attacker_row(p, c)))
         for p, c in attackers_with_counts],
        ensure_ascii=False, indent=2,
    )


def attackers_xlsx(attackers_with_counts):
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = 'attacker_profiles'
    ws.append(ATTACKER_COLUMNS)
    for p, count in attackers_with_counts:
        ws.append(_attacker_row(p, count))
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()

"""
后台任务模块
"""
from datetime import datetime, timedelta

from flask import current_app

from app import create_app
from app.extensions import db
from app.models import AttackEvent, AttackerProfile
from app.settings_store import get_setting
from app import email_utils


def cleanup_old_data(days=None):
    """清理指定天数前的数据。days 为 None 时读取系统设置 data_retention_days。"""
    app = create_app()
    with app.app_context():
        if days is None:
            days = int(get_setting('data_retention_days', 30))
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        # 删除旧的攻击事件
        old_events = AttackEvent.query.filter(AttackEvent.timestamp < cutoff_date).all()
        for event in old_events:
            db.session.delete(event)

        # 删除没有攻击事件的攻击者档案
        old_profiles = AttackerProfile.query.filter(
            AttackerProfile.last_seen < cutoff_date,
            ~AttackerProfile.attacks.any()
        ).all()
        for profile in old_profiles:
            db.session.delete(profile)

        db.session.commit()
        current_app.logger.info(
            "清理了 %d 个攻击事件和 %d 个攻击者档案(保留 %d 天)",
            len(old_events), len(old_profiles), days,
        )


def generate_daily_report():
    """生成每日报告并通过邮件发送给开启通知的管理员"""
    app = create_app()
    with app.app_context():
        yesterday = datetime.utcnow().date() - timedelta(days=1)
        stats = email_utils.build_daily_stats(yesterday)
        sent = email_utils.send_daily_report(yesterday)
        current_app.logger.info(
            "每日报告 - %s: 攻击事件 %d, 新攻击者 %d, 邮件发送给 %d 名管理员",
            yesterday, stats['events'], stats['new_attackers'], sent,
        )


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == 'cleanup':
            days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
            cleanup_old_data(days)
        elif sys.argv[1] == 'report':
            generate_daily_report()
    else:
        print("用法: python tasks.py [cleanup|report] [days]")

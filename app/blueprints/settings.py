from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from ..decorators import super_admin_required
from ..extensions import db
from ..models import User
from ..forms import ChangePasswordForm
from .. import settings_store
import hashlib

settings_bp = Blueprint('settings', __name__)


BOOL_KEYS = [
    'register_enabled', 'geoip_enabled',
    'email_alerts_enabled',
    'smtp_enabled', 'smtp_use_tls',
    'daily_report_enabled',
    'threat_intel_enabled',
]
INT_KEYS = ['data_retention_days', 'smtp_port',
            'abuseipdb_threshold', 'threat_intel_cache_hours']
STRING_KEYS = [
    'api_rate_limit', 'daily_report_time',
    'smtp_host', 'smtp_username', 'smtp_sender',
    'abuseipdb_api_key',
]


@settings_bp.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


@settings_bp.route('/system-settings', methods=['GET', 'POST'])
@login_required
@super_admin_required
def system_settings():
    if request.method == 'POST':
        try:
            for key in BOOL_KEYS:
                settings_store.set_setting(key, request.form.get(key) == 'on')
            for key in INT_KEYS:
                raw = (request.form.get(key) or '').strip()
                if raw:
                    settings_store.set_setting(key, int(raw))
            for key in STRING_KEYS:
                settings_store.set_setting(key, (request.form.get(key) or '').strip())
            # SMTP 密码留空表示不修改
            smtp_password = request.form.get('smtp_password') or ''
            if smtp_password.strip():
                settings_store.set_setting('smtp_password', smtp_password.strip())
            settings_store.clear_cache()
            from ..audit import audit
            audit('update_system_settings', '修改系统设置')
            flash('系统设置已保存并立即生效', 'success')
        except (ValueError, KeyError) as e:
            db.session.rollback()
            flash(f'保存失败：{e}', 'error')
        return redirect(url_for('settings.system_settings'))

    return render_template('system_settings.html', s=settings_store.all_settings())


@settings_bp.route('/system-settings/test-email', methods=['POST'])
@login_required
@super_admin_required
def test_email():
    """发送 SMTP 测试邮件(使用已保存的系统设置)。"""
    recipient = (request.form.get('test_email') or '').strip()
    if not recipient:
        flash('请输入收件邮箱', 'error')
    else:
        from ..email_utils import send_test_email
        if send_test_email(recipient):
            flash(f'测试邮件已发送至 {recipient}', 'success')
        else:
            flash('测试邮件发送失败,请检查 SMTP 是否已启用及配置是否正确(详见日志)', 'error')
    return redirect(url_for('settings.system_settings'))


@settings_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.check_password(form.old_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            from ..audit import audit
            audit('change_password', f'用户 {current_user.username} 修改密码')
            flash('密码修改成功', 'success')
        else:
            flash('原密码错误', 'error')
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'error')
    return redirect(url_for('settings.settings'))


@settings_bp.route('/update-notifications', methods=['POST'])
@login_required
def update_notifications():
    email_notifications = request.form.get('email_notifications') == 'on'
    # Store in user profile or separate settings table
    current_user.email_notifications = email_notifications
    db.session.commit()
    flash('通知设置已更新', 'success')
    return redirect(url_for('settings.settings'))


@settings_bp.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    # Delete user account
    from ..audit import audit
    name = current_user.username
    audit('delete_account', f'删除账号 {name}')
    db.session.delete(current_user)
    db.session.commit()
    flash('账号已删除', 'success')
    return redirect(url_for('auth.login'))


@settings_bp.route('/toggle-theme', methods=['POST'])
@login_required
def toggle_theme():
    theme = request.json.get('theme', 'light')
    # Store theme preference in user profile or session
    current_user.theme_preference = theme
    db.session.commit()
    return jsonify({'status': 'success', 'theme': theme})

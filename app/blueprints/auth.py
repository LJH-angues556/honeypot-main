from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, abort
from flask_login import login_user, logout_user, login_required, current_user  # pyright: ignore[reportMissingImports]
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import hashlib
from ..extensions import db, limiter
from ..models import User
from ..forms import (
    LoginForm, RegistrationForm, ForgotPasswordForm, ResetPasswordForm,
)
from ..settings_store import get_setting


auth_bp = Blueprint('auth', __name__)

RESET_SALT = 'password-reset'
RESET_MAX_AGE = 3600  # 重置链接 1 小时有效


def _password_version(user) -> str:
    """密码版本号:对完整密码哈希取摘要。

    不能直接取 password_hash 前缀——werkzeug 哈希以算法名开头
    (pbkdf2:sha256:...),改密后前缀不变,旧令牌将无法失效。
    """
    return hashlib.sha256((user.password_hash or '').encode()).hexdigest()[:16]


def _reset_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'], salt=RESET_SALT)


def generate_reset_token(user):
    """生成密码重置令牌。

    内含当前密码版本号,一旦密码被修改,旧令牌立即失效(一次性)。
    """
    return _reset_serializer().dumps({
        'uid': user.id,
        'v': _password_version(user),
    })


def load_reset_user(token):
    """校验重置令牌。返回 (user|None, error|None),error ∈ {'expired','invalid'}。"""
    try:
        data = _reset_serializer().loads(token, max_age=RESET_MAX_AGE)
    except SignatureExpired:
        return None, 'expired'
    except BadSignature:
        return None, 'invalid'
    user = db.session.get(User, data.get('uid'))
    if not user or _password_version(user) != data.get('v'):
        return None, 'invalid'
    return user, None


@auth_bp.route('/')
def root():
    return redirect(url_for('admin.dashboard'))


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and not user.is_active:
            from ..audit import audit
            audit('login_failed', f'用户名 {form.username.data} 账号已被禁用')
            flash('账号已被禁用,请联系超级管理员', 'error')
        elif user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            from ..audit import audit
            audit('login', f'用户 {user.username} 登录成功')
            return redirect(url_for('admin.dashboard'))
        else:
            from ..audit import audit
            audit('login_failed', f'用户名 {form.username.data} 密码错误')
            flash('用户名或密码错误', 'error')
    return render_template('login.html', form=form)


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def register():
    # 注册开关:系统设置(DB)优先,环境变量 REGISTER_ENABLED 兜底;关闭时 404
    register_enabled = get_setting(
        'register_enabled', current_app.config.get('REGISTER_ENABLED', False)
    )
    if not register_enabled:
        abort(404)

    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role='viewer'
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('注册成功！请登录', 'success')
        return redirect(url_for('auth.login'))
    return render_template('register.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    from ..audit import audit
    name = current_user.username
    logout_user()
    audit('logout', f'用户 {name} 登出')
    return redirect(url_for('auth.login'))


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard'))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter(db.func.lower(User.email) == email).first()
        if user:
            reset_url = url_for(
                'auth.reset_password', token=generate_reset_token(user), _external=True
            )
            html = render_template(
                'email/password_reset.html', user=user, reset_url=reset_url
            )
            # SMTP 未启用或发送失败时不抛异常(仅日志),避免影响统一响应
            from ..email_utils import send_email
            send_email(user.email, '【蜜罐系统】密码重置', html)
        # 无论邮箱是否存在都给出相同提示,防止账号枚举
        flash('如果该邮箱已注册,重置链接将在几分钟内发送到邮箱(链接 1 小时内有效)', 'success')
        return redirect(url_for('auth.login'))
    return render_template('forgot_password.html', form=form)


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard'))

    user, error = load_reset_user(token)
    if error == 'expired':
        flash('重置链接已过期,请重新申请', 'error')
        return redirect(url_for('auth.forgot_password'))
    if user is None:
        flash('重置链接无效,请重新申请', 'error')
        return redirect(url_for('auth.forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        # 密码已变,令牌中的版本号不再匹配,旧链接即刻失效
        flash('密码已重置,请使用新密码登录', 'success')
        return redirect(url_for('auth.login'))
    return render_template('reset_password.html', form=form)



import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

from .extensions import db, migrate, login_manager, csrf, limiter, mail, create_redis_client
from .models import User


def _configure_logging(app):
    """配置文件日志:logs/app.log,10MB 轮转,保留 5 个;同时输出到控制台。"""
    if any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers):
        return  # 已配置过,避免重复添加 handler

    # 去掉 Flask 默认的 stderr handler,改用统一格式输出,避免控制台重复
    from flask.logging import default_handler
    app.logger.removeHandler(default_handler)

    app.logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        '%(asctime)s %(levelname)s [%(name)s] %(message)s'
    )

    logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    file_handler = RotatingFileHandler(
        os.path.join(logs_dir, 'app.log'),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding='utf-8',
    )
    file_handler.setFormatter(fmt)
    app.logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    app.logger.addHandler(stream_handler)


def create_app(config_object='config.Config'):
    load_dotenv()
    app = Flask(
        __name__,
        template_folder='../templates',
        static_folder='../static',
    )
    app.config.from_object(config_object)

    # 生产环境位于 Nginx 反向代理之后,信任代理注入的 X-Forwarded-* 头,
    # 使 request.remote_addr / 限流取到真实客户端 IP
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    _configure_logging(app)

    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    csrf.init_app(app)
    # 限流存储必须在 init_app 之前通过配置指定,事后给 limiter.storage_uri
    # 赋值不会生效(会退化成各 worker 独立的内存计数)
    if not app.config.get('RATELIMIT_STORAGE_URI'):
        redis_pwd = app.config.get('REDIS_PASSWORD')
        auth = f':{redis_pwd}@' if redis_pwd else ''
        app.config['RATELIMIT_STORAGE_URI'] = (
            f"redis://{auth}{app.config['REDIS_HOST']}:"
            f"{app.config['REDIS_PORT']}/{app.config['REDIS_DB']}"
        )
    limiter.init_app(app)

    # 邮件(实际 SMTP 参数发送时可被系统设置覆盖,见 app/email_utils.py)
    mail.init_app(app)

    # Redis client
    app.redis = create_redis_client(app)

    # RQ 异步任务队列。注意 RQ 不兼容 decode_responses=True,
    # 因此使用独立的原生 Redis 连接(区别于 app.redis)
    app.task_queue = None
    if app.config.get('RQ_ENABLED'):
        import redis as _redis
        from rq import Queue
        rq_redis = _redis.Redis(
            host=app.config['REDIS_HOST'],
            port=app.config['REDIS_PORT'],
            db=app.config['REDIS_DB'],
            password=app.config['REDIS_PASSWORD'],
        )
        app.task_queue = Queue(
            app.config['RQ_QUEUE_NAME'],
            connection=rq_redis,
            default_timeout=app.config['RQ_JOB_TIMEOUT'],
        )

    # Blueprints
    from .blueprints.auth import auth_bp
    from .blueprints.admin import admin_bp
    from .blueprints.api import api_bp
    from .blueprints.settings import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(settings_bp, url_prefix='/admin')

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # 向所有模板注入全局变量(注册开关等)
    @app.context_processor
    def inject_globals():
        from .settings_store import get_setting
        return {
            'register_enabled': get_setting(
                'register_enabled', app.config.get('REGISTER_ENABLED', False)
            ),
        }

    # 错误处理器:使用独立的 errors/ 模板,不依赖登录后的布局
    @app.errorhandler(403)
    def forbidden(error):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    return app
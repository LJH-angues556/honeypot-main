import os


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-change-me')
    API_SECRET_KEY = os.getenv('API_SECRET_KEY', 'api-secret-change-me')

    MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
    MYSQL_PORT = int(os.getenv('MYSQL_PORT', '3306'))
    MYSQL_USER = os.getenv('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', 'password')
    MYSQL_DB = os.getenv('MYSQL_DB', 'honeypot')

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}?charset=utf8mb4"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
    REDIS_DB = int(os.getenv('REDIS_DB', '0'))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)

    # Flask-Login
    REMEMBER_COOKIE_DURATION_DAYS = int(os.getenv('REMEMBER_COOKIE_DURATION_DAYS', '7'))

    # 注册开关:蜜罐管理后台默认不开放注册,账号由管理员通过 manage.py 创建
    REGISTER_ENABLED = os.getenv('REGISTER_ENABLED', 'false').lower() in ('1', 'true', 'yes')

    # GeoIP 归属地解析(ip-api.com 免费版)
    GEOIP_ENABLED = os.getenv('GEOIP_ENABLED', 'true').lower() in ('1', 'true', 'yes')
    GEOIP_API_URL = os.getenv('GEOIP_API_URL', 'http://ip-api.com/json/{ip}')
    GEOIP_TIMEOUT = float(os.getenv('GEOIP_TIMEOUT', '3'))

    # 威胁情报(任务4.3;系统设置页可覆盖)
    THREAT_INTEL_ENABLED = os.getenv('THREAT_INTEL_ENABLED', 'true').lower() in ('1', 'true', 'yes')

    # SMTP 邮件(系统设置页可覆盖;这里是环境变量兜底配置)
    MAIL_SERVER = os.getenv('SMTP_HOST', 'localhost')
    MAIL_PORT = int(os.getenv('SMTP_PORT', '587'))
    MAIL_USE_TLS = os.getenv('SMTP_USE_TLS', 'true').lower() in ('1', 'true', 'yes')
    MAIL_USE_SSL = os.getenv('SMTP_USE_SSL', 'false').lower() in ('1', 'true', 'yes')
    MAIL_USERNAME = os.getenv('SMTP_USERNAME') or None
    MAIL_PASSWORD = os.getenv('SMTP_PASSWORD') or None
    MAIL_DEFAULT_SENDER = os.getenv('SMTP_SENDER') or None
    SMTP_ENABLED = os.getenv('SMTP_ENABLED', 'false').lower() in ('1', 'true', 'yes')

    # RQ 异步队列(关闭时任务在请求线程内同步执行,便于测试/单机轻量部署)
    RQ_ENABLED = os.getenv('RQ_ENABLED', 'true').lower() in ('1', 'true', 'yes')
    RQ_QUEUE_NAME = os.getenv('RQ_QUEUE_NAME', 'honeypot')
    RQ_JOB_TIMEOUT = int(os.getenv('RQ_JOB_TIMEOUT', '180'))


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False



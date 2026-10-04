# 蜜罐系统 Flask 应用镜像
# 选 3.11-slim:Flask 2.3.3 及其钉版依赖在 3.11 上兼容性最好,slim 体积小
FROM python:3.11-slim

# 运行时环境:不缓冲 stdout(日志即时输出)、不写 .pyc、固定 FLASK_APP
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_APP=app \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 先单独复制依赖清单,利用 docker 层缓存(代码变动不重装依赖)
COPY requirements.txt .
RUN pip install -r requirements.txt

# 复制项目全部代码
COPY . .

# entrypoint 赋予执行权限
RUN chmod +x /app/entrypoint.sh

EXPOSE 5000

# entrypoint:等待 MySQL → 迁移 → 建管理员 → 启动 gunicorn
ENTRYPOINT ["/app/entrypoint.sh"]

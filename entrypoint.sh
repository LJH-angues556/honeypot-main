#!/bin/sh
set -e

echo "[entrypoint] Waiting for MySQL at $MYSQL_HOST:$MYSQL_PORT ..."

# 用 PyMySQL(已在 requirements 中)轮询 MySQL 可连接,slim 镜像无 mysql 客户端
python - <<'PY'
import os, sys, time
import pymysql

host = os.getenv('MYSQL_HOST', 'mysql')
port = int(os.getenv('MYSQL_PORT', '3306'))
user = os.getenv('MYSQL_USER', 'root')
password = os.getenv('MYSQL_PASSWORD', '')

for i in range(60):
    try:
        conn = pymysql.connect(
            host=host, port=port, user=user, password=password,
            connect_timeout=3,
        )
        conn.close()
        print(f"[entrypoint] MySQL is up at {host}:{port}")
        sys.exit(0)
    except Exception as e:
        print(f"[entrypoint] MySQL not ready yet ({e}), retry {i + 1}/60 ...")
        time.sleep(2)

print("[entrypoint] ERROR: MySQL did not become ready in time", file=sys.stderr)
sys.exit(1)
PY

echo "[entrypoint] Applying database migrations (flask db upgrade) ..."
flask db upgrade

echo "[entrypoint] Ensuring admin user exists (manage.py all) ..."
# create_admin 在管理员已存在时会跳过,失败不阻断应用启动
python manage.py all || echo "[entrypoint] WARNING: manage.py all returned non-zero, continuing anyway."

echo "[entrypoint] Starting: $@"
# 实际启动进程由 docker-compose 的 command 指定(app=gunicorn)
exec "$@"

#!/usr/bin/env python3
"""数据库迁移管理脚本

使用 Flask-Migrate 原生 CLI,不再依赖 flask_script(Flask 2.3 不兼容)。
用法:
    python migrate.py db init                 # 初始化迁移目录(已完成可跳过)
    python migrate.py db migrate -m "msg"      # 生成迁移脚本
    python migrate.py db upgrade               # 应用迁移到数据库
    python migrate.py db downgrade             # 回退一步
    python migrate.py db --help                # 查看所有子命令

或直接使用 flask 命令(等价):
    flask db migrate -m "msg"
"""
import os

from flask.cli import FlaskGroup

from app import create_app

os.environ.setdefault('FLASK_APP', 'app')

app = create_app()

if __name__ == '__main__':
    FlaskGroup(create_app=create_app).main()

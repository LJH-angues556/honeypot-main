#!/usr/bin/env python3
"""蜜罐系统启动脚本"""
import os

from app import create_app

app = create_app()

if __name__ == '__main__':
    os.environ.setdefault('FLASK_APP', 'app')
    # debug 默认关闭,通过 DEBUG=1 或 FLASK_ENV=development 开启
    debug = os.getenv('FLASK_ENV', '').lower() == 'development' or os.getenv('DEBUG', '').lower() in ('1', 'true', 'yes')
    app.run(host='0.0.0.0', port=5000, debug=debug)

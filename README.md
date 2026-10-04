# Honeypot 蜜罐管理系统

一个用于收集、展示和分析攻击行为的 Web 蜜罐系统。蜜罐节点通过带 HMAC 签名的 HTTP API 上报攻击事件，管理后台提供攻击事件查询、攻击者画像（GeoIP 归属地）、数据统计图表与全球分布地图，并支持深浅双主题。系统内置开箱即用的 HTTP 诱饵蜜罐（phpMyAdmin / WordPress / 通用后台伪装页），可自动注册节点、上报心跳与捕获的凭据/攻击载荷。

个人毕业设计项目。

## 功能特性

- **HTTP 蜜罐诱饵**：内置独立运行的蜜罐程序（`honeypots/`），提供 phpMyAdmin、WordPress、后台登录三类伪装页面；自动识别 SQL 注入（high）、XSS（medium）、路径遍历（medium）、登录尝试（low）与探测（info），捕获表单凭据并异步上报；启动后自动向平台注册节点并每 60 秒上报心跳
- **多协议蜜罐**：除 HTTP 外新增 SSH（端口 2222，任意密码可登录的假 shell，危险命令伪装拦截）、Telnet（端口 2323，Cisco 风格横幅与假命令）、Redis（端口 6379，RESP 协议解析，伪造响应并识别未授权访问/利用/RCE 尝试）；所有蜜罐共用统一上报客户端，自动注册节点并心跳
- **告警规则引擎**：`/admin/alerts` 可视化创建规则，支持 4 类规则——高危严重级别、IP 频率阈值、新攻击者、新国家；规则含冷却时间避免重复告警，触发后写入告警历史（`/admin/alert-history`）并通过邮件通知
- **实时数据推送（SSE）**：`/admin/stream` 基于 Redis pub/sub 的服务器推送事件流；仪表盘统计数字与最近事件表实时刷新（连接状态指示器 + 新行高亮），攻击事件列表页弹出新事件提示气泡；EventSource 原生自动重连，Redis 不可用时返回 503 供浏览器退避
- **威胁情报对接**：默认使用 Spamhaus DROP/EDROP 开源恶意网段（零配置，每 6 小时自动同步，本地网段匹配）；可选配置 AbuseIPDB API Key 做单 IP 信誉评分（阈值可配）；查询结果按 TTL 缓存入库，攻击者画像页显示恶意标记与情报来源，仪表盘显示已知威胁 IP 占比
- **操作审计日志**：`/admin/audit-logs` 记录登录、封禁/解封、规则增删、设置变更、用户管理、数据导出等关键操作，含操作人、IP、User-Agent 与时间；异常仅记日志不阻断业务
- **数据导出增强**：攻击事件与攻击者画像支持 **CSV / JSON / Excel(openpyxl)** 三种格式导出（CSV 带 UTF-8 BOM），复用列表筛选条件；超过 2000 条自动走 RQ 异步生成并邮件发送给请求人，避免长请求超时；每次导出均记入审计日志
- **多维筛选**：攻击事件支持 IP、方法、严重级别、蜜罐服务、攻击签名（模糊）、国家、起止时间筛选；攻击者画像支持国家、封禁状态、攻击次数范围、首次/最近出现时间筛选；筛选条件在分页与导出间保持
- **蜜罐节点管理**：`/admin/nodes` 节点列表（在线/离线状态、5 分钟心跳窗口）、手动创建节点（下发 HMAC 密钥）、删除节点（保留历史事件）；攻击事件关联上报节点
- **攻击捕获 API**：`POST /api/capture`，HMAC-SHA256 签名鉴权 + 5 分钟时间戳窗口 + 频率限制；节点密钥（`X-Node-Key`）鉴权、可信节点透传真实攻击者 IP
- **攻击者画像**：按 IP 聚合，自动补全国家 / 城市 / ASN / ISP（ip-api.com）
- **IP 黑名单**：一键封禁 / 解封攻击者、封禁原因与时间、批量解封、黑名单列表筛选、TXT/CSV 导出（CSV 带 BOM，可直接用于 iptables 等防火墙）
- **系统设置**：`/admin/system-settings` 在线配置自助注册开关、GeoIP 开关、数据保留天数、API 限流、SMTP 邮件、告警/日报订阅等，**保存后即时生效**（无需重启），支持发送 SMTP 测试邮件
- **邮件通知**（Flask-Mail）：高危/严重攻击实时告警（异步队列发送）、每日攻击统计日报（定时调度器）、忘记密码重置邮件（一次性令牌，1 小时有效）；SMTP 未配置或发送失败仅记录日志，不阻断业务
- **密码找回**：`/forgot-password` 提交邮箱 → 签名重置链接 → `/reset-password/<token>` 设置新密码；统一响应文案防止账号枚举；接口级限流
- **异步任务队列**（RQ + Redis）：GeoIP 补全、告警邮件入队后台执行，API 快速返回；队列关闭或入队失败自动降级为同步执行；独立调度器容器负责每日报告与数据清理
- **管理后台**：仪表盘、攻击事件列表与详情（含上报节点）、攻击者列表与详情、统计分析、世界地图、数据库查看、蜜罐节点、IP 黑名单、系统设置
- **权限控制**：三级角色体系——超级管理员（用户管理、系统设置、节点增删）、管理员（封禁/规则/模拟攻击等写操作）、普通用户（全部页面只读）；`/admin/users` 用户管理（创建用户、角色调整、启用/禁用、重置密码，含最后超管保护）；注册功能默认关闭
- **模拟攻击演示**：仪表盘快捷操作区支持一键随机生成，或自定义 IP / 国家 / 严重级别 / 蜜罐服务 / 攻击签名 / User-Agent，并支持批量生成 1-100 条
- **双主题 UI**：CSS 变量驱动的浅色 / 深色主题，偏好持久化
- **本地化图表**：ECharts 5 与世界地图 GeoJSON 内置于 `static/`，完全离线可用，无任何 CDN 依赖
- **一键部署**：Docker Compose 编排 MySQL + Redis + Flask(gunicorn gthread) + Nginx + RQ Worker + 定时调度器 + 4 类蜜罐，共 10 个服务

## 技术栈

| 层 | 技术 |
| --- | --- |
| Web 框架 | Flask 2.3（应用工厂 + Blueprint） |
| ORM / 迁移 | Flask-SQLAlchemy 3、Flask-Migrate(Alembic) |
| 认证 / 表单 | Flask-Login、Flask-WTF(CSRF)、WTForms、itsdangerous（重置令牌） |
| 邮件 | Flask-Mail（SMTP） |
| 异步队列 | RQ（Redis 后端）+ 独立定时调度器 |
| 限流 | Flask-Limiter + Redis |
| 数据库 / 缓存 | MySQL 8.0、Redis 7 |
| 蜜罐 | 独立 Python 程序（`honeypots/`）：HTTP(flask)、SSH(paramiko)、Telnet(socket)、Redis(原生 RESP) |
| 前端 | 原生 HTML/CSS/JS、ECharts 5（本地内置，无 CDN）、EventSource(SSE) |
| 服务 | gunicorn(gthread worker)、Nginx |
| 测试 | pytest（SQLite 内存库，125 个用例，核心覆盖率 74%） |

## 架构

```
                ┌──────────── HTTP 蜜罐容器 (8080/8081) ───────────┐
攻击者 ─────────▶│ phpMyAdmin / WordPress / 通用后台 诱饵 + 攻击检测 │
                └───────┬───────────────────────────────────────────┘
                        │
                ┌───────┴─────────────── SSH(2222) / Telnet(2323) / Redis(6379) ──┐
                │  假 shell / Cisco 横幅 / RESP 伪造响应,识别利用与 RCE 尝试        │
                └───────────────────────────┬───────────────────────────────────────┘
                                            │ 注册 / 心跳 / 事件上报(HMAC 签名)
                                            ▼
  Nginx :80  ──静态资源直供──▶ /static
      │ 反向代理(/admin/stream 关缓冲转发 SSE 长连接)
      ▼
 Flask (gunicorn gthread :5000)
   ├─ auth 蓝图     登录 / 登出 / 注册(可关闭) / 忘记&重置密码
   ├─ admin 蓝图    /admin/* 后台:事件/画像/统计/节点/黑名单/设置/用户管理
   │                └─ /admin/stream  SSE 实时事件流(登录用户)
   ├─ api 蓝图      /api/capture /api/node/register /api/node/heartbeat
   └─ settings 蓝图 主题 / 通知偏好 / 注销 / 系统设置
      │
      ├── MySQL    用户、攻击者画像、攻击事件、系统设置、蜜罐节点、威胁情报缓存
      ├── Redis    接口限流 + RQ 队列 + SSE pub/sub 频道
      └── RQ honeypot 队列 ──▶ rq-worker(GeoIP 补全 / 告警邮件 / 威胁情报查询)
                               scheduler(每日报告 + 数据清理 + 威胁情报 feed 每 6h 刷新)
      └── SMTP     告警 / 日报 / 密码重置(SMTP 未配置时仅记日志)
```

## 快速开始（Docker Compose）

前置条件：已安装 Docker 与 Docker Compose 插件。

1. 按需修改根目录 `.env`（**生产环境务必替换两个密钥和管理员密码**）：

   ```bash
   SECRET_KEY=...
   API_SECRET_KEY=...
   MYSQL_PASSWORD=...
   ADMIN_PASSWORD=...
   ```

2. 在项目根目录启动全部服务：

   ```bash
   docker compose up -d
   ```

   `app` 容器启动时会自动等待 MySQL 就绪 → 执行 `flask db upgrade` → 执行 `manage.py all`（建表 + 创建管理员）→ 启动 gunicorn。启动后共 10 个容器：

   | 容器 | 作用 | 暴露端口 |
   | --- | --- | --- |
   | `honeypot-nginx` | 反向代理 + 静态资源 | **80**（管理后台/API） |
   | `honeypot-app` | Flask 应用（gunicorn 4×8 gthread） | 仅容器网络 |
   | `honeypot-mysql` | MySQL 8.0 | 仅容器网络 |
   | `honeypot-redis` | Redis 7（限流 + RQ 队列） | 仅容器网络 |
   | `honeypot-rq-worker` | RQ worker，消费 GeoIP / 告警邮件 / 大数据导出任务 | 无 |
   | `honeypot-scheduler` | 定时调度（每日报告、数据清理） | 无 |
   | `honeypot-http` | HTTP 诱饵蜜罐（phpMyAdmin/WordPress） | **8080 / 8081** |
   | `honeypot-ssh` | SSH 诱饵蜜罐（假 shell） | **2222** |
   | `honeypot-telnet` | Telnet 诱饵蜜罐（Cisco 风格） | **2323** |
   | `honeypot-redis-hp` | Redis 诱饵蜜罐（RESP 伪造） | **6379** |

3. 浏览器访问 <http://localhost>，使用 `.env` 中的 `ADMIN_USERNAME` / `ADMIN_PASSWORD` 登录。HTTP 蜜罐诱饵分别位于 <http://localhost:8080/phpmyadmin/index.php> 与 <http://localhost:8081/wp-login.php>；SSH/Telnet/Redis 蜜罐可直接用对应客户端连接（如 `ssh -p 2222 root@localhost`、`telnet localhost 2323`、`redis-cli -p 6379`），任意凭据均可进入假交互。所有蜜罐启动后会自动在「蜜罐节点」页注册为在线节点。

> 修改了 `entrypoint.sh`、Python 代码或模板后需 `docker compose up -d --build` 重建镜像；仅重启不会让镜像内文件更新。

常用命令：

```bash
docker compose logs -f app          # 查看应用日志
docker compose logs -f rq-worker    # 查看异步任务消费日志
docker compose logs -f http-honeypot  # 查看蜜罐注册/心跳/上报日志
docker compose down                 # 停止并移除容器(数据卷保留)
docker compose down -v              # 连同数据库数据一起清除
```

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SECRET_KEY` | `dev-secret-change-me` | Flask 会话 / CSRF 密钥，生产必须修改 |
| `API_SECRET_KEY` | `api-secret-change-me` | `/api/capture` 与节点注册的 HMAC 签名密钥 |
| `MYSQL_HOST` / `MYSQL_PORT` | `localhost` / `3306` | MySQL 地址（Compose 内自动覆盖为 `mysql`） |
| `MYSQL_USER` / `MYSQL_PASSWORD` | `root` / `password` | MySQL 账号密码 |
| `MYSQL_DB` | `honeypot` | 数据库名 |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` | `localhost` / `6379` / `0` | Redis 连接（Compose 内自动覆盖 host 为 `redis`） |
| `REDIS_PASSWORD` | 空 | Redis 密码 |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | 无（交互式输入） | 首次启动自动创建的管理员账号 |
| `REGISTER_ENABLED` | `false` | 是否开放自助注册（可在系统设置页运行时修改，即时生效） |
| `GEOIP_ENABLED` | `true` | 是否调用 ip-api.com 解析 IP 归属地（系统设置页可运行时关闭） |
| `GEOIP_API_URL` | `http://ip-api.com/json/{ip}` | GeoIP 接口模板 |
| `GEOIP_TIMEOUT` | `3` | GeoIP 请求超时秒数 |
| `THREAT_INTEL_ENABLED` | `true` | 威胁情报总开关（系统设置页可运行时关闭；AbuseIPDB Key/阈值/缓存 TTL 均在系统设置页配置） |
| `REMEMBER_COOKIE_DURATION_DAYS` | `7` | 记住登录天数 |
| `SMTP_ENABLED` | `false` | 是否启用邮件发送；未启用时所有邮件仅写日志 |
| `SMTP_HOST` / `SMTP_PORT` | `localhost` / `587` | SMTP 服务器地址与端口 |
| `SMTP_USE_TLS` / `SMTP_USE_SSL` | `true` / `false` | STARTTLS / SSL 开关（二者一般只开一个） |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | 空 | SMTP 认证账号 / 授权码（系统设置页也可配置，密码留空表示不修改） |
| `SMTP_SENDER` | 空 | 发件人地址，如 `蜜罐系统 <no-reply@example.com>` |
| `RQ_ENABLED` | `true` | 是否启用 RQ 异步队列；关闭或入队失败时任务同步执行 |
| `RQ_QUEUE_NAME` | `honeypot` | RQ 队列名（需与 rq-worker 命令一致） |
| `RQ_JOB_TIMEOUT` | `180` | 单个异步任务超时秒数 |
| `HONEYPOT_API_URL` | `http://app:5000` | 蜜罐上报平台地址（`honeypots/` 程序读取） |
| `HONEYPOT_NODE_NAME` | `http-honeypot-1` | 蜜罐节点名（同名重复注册幂等复用密钥） |
| `HONEYPOT_PORTS` | `8080:phpmyadmin,8081:wordpress` | 蜜罐监听端口与诱饵类型映射 |
| `HONEYPOT_PUBLISH_8080` / `HONEYPOT_PUBLISH_8081` | `8080` / `8081` | 宿主机映射端口（改为空可不对宿主机暴露） |
| `HONEYPOT_SSH_PORT` / `HONEYPOT_SSH_PUBLISH` | `2222` / `2222` | SSH 蜜罐容器内端口 / 宿主机映射端口 |
| `HONEYPOT_TELNET_PORT` / `HONEYPOT_TELNET_PUBLISH` | `2323` / `2323` | Telnet 蜜罐容器内端口 / 宿主机映射端口 |
| `HONEYPOT_REDIS_PORT` / `HONEYPOT_REDIS_PUBLISH` | `6379` / `6379` | Redis 蜜罐容器内端口 / 宿主机映射端口 |
| `HONEYPOT_SSH_ACCEPT_ANY` | `true` | SSH 蜜罐是否接受任意密码登录（生产诱饵建议 true） |

## 攻击上报 API

### 鉴权规则

- 请求头携带：
  - `X-API-Timestamp`：当前 Unix 秒级时间戳，与服务器时差超过 **300 秒**拒绝
  - `X-API-Signature`：HMAC-SHA256 十六进制摘要
- 签名内容：`HMAC_SHA256(API_SECRET_KEY, timestamp + 原始请求体字节)`
- 限流：每 IP 每分钟 100 次
- 客户端 IP 取 `X-Forwarded-For` 链首地址，否则取直连地址

### 请求体字段（JSON，均可选）

| 字段 | 说明 |
| --- | --- |
| `service` | 蜜罐服务标识，如 `web`、`ssh`、`http-phpmyadmin`（默认 `web`） |
| `severity` | 严重级别 `info` / `low` / `medium` / `high` / `critical`（默认 `low`） |
| `signature` | 攻击特征名，如 `sql_injection`、`xss_attempt`、`path_traversal`、`login_attempt`、`probe` |
| `node_key` | 蜜罐节点密钥；也可通过 `X-Node-Key` 请求头传递。匹配后事件关联到该节点，密钥本身不落库 |
| `client_ip` | 可信节点透传的真实攻击者 IP（经 IP 格式校验，非法时回退直连地址） |
| `method` / `path` / `headers` | 节点代为捕获的原始 HTTP 请求信息（存于事件 payload） |
| `payload` | 任意附加 JSON，如表单凭据 `{"username": "...", "password": "..."}` |

事件入库后，GeoIP 补全与高危告警通过 RQ 异步执行（队列关闭时同步降级）。

### curl 示例

```bash
SECRET='h0n3yp0t-7c4f9b2e1a8d6053-secre7-change-me'
BODY='{"service":"web","severity":"high","signature":"sql_injection"}'
TS=$(date +%s)
SIG=$(printf '%s%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')

curl -X POST http://localhost/api/capture \
  -H "Content-Type: application/json" \
  -H "X-API-Timestamp: $TS" \
  -H "X-API-Signature: $SIG" \
  -H "X-Forwarded-For: 1.2.3.4" \
  -d "$BODY"
# {"event_id":1,"status":"ok"}
```

## 蜜罐节点 API

蜜罐程序或外部采集器通过以下接口接入平台（签名规则同上，密钥同为 `API_SECRET_KEY`）：

### `POST /api/node/register`

注册（或同名幂等取回）一个节点。请求体：

```json
{"name": "http-honeypot-1", "service_type": "http"}
```

返回：

```json
{"node_id": 1, "node_key": "随机生成的节点密钥", "heartbeat_interval": 60, "heartbeat_timeout": 300}
```

- 同名节点重复注册时复用既有 `node_key`（容器重建不产生重复节点）
- 注册接口本身需要 HMAC 签名（与 `/api/capture` 相同规则）

### `POST /api/node/heartbeat`

请求体 `{}` 或 `{"node_key": "..."}`，**只需** `X-Node-Key`（或请求体 `node_key`）鉴权，无需 HMAC 签名；鉴权成功刷新 `last_heartbeat` 与节点来源 IP，返回 `{"status":"ok"}`；密钥无效返回 401。平台以 **5 分钟**心跳窗口判定节点在线状态。

## 本地开发

需 Python 3.11+、本地 MySQL 与 Redis（也可自行改 `SQLALCHEMY_DATABASE_URI` 使用 SQLite）。

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 1. 建表并创建管理员
python manage.py all

# 2. 启动开发服务器
python run.py                      # 默认 http://127.0.0.1:5000
```

### 数据库迁移

仅在修改 `app/models.py` 表结构后需要：

```bash
flask db migrate -m "描述本次变更"
flask db upgrade
```

### 运行测试

测试使用 SQLite 内存库，且自动关闭 CSRF、GeoIP 与限流，无需外部服务：

```bash
python -m pytest tests/ -v
```

无本地 Python 环境时可用 Docker 运行：

```bash
docker run --rm -v "${PWD}:/app" -w /app python:3.11-slim \
  sh -c "pip install -q -r requirements.txt && python -m pytest tests/ -v"
```

## 目录结构

```
honeypot-main/
├── app/
│   ├── __init__.py        # create_app 工厂、错误页、ProxyFix、task_queue
│   ├── decorators.py      # admin_required / super_admin_required 装饰器
│   ├── extensions.py      # db / migrate / login / csrf / limiter / redis / mail
│   ├── models.py          # User(三级角色) / AttackerProfile / AttackEvent / SystemSetting
│   │                      # HoneypotNode / AlertRule / AlertHistory / AuditLog / ThreatIntelRecord
│   ├── forms.py           # 登录 / 注册 / 忘记密码 / 重置密码表单
│   ├── geoip.py           # IP 归属地查询(受 geoip_enabled 设置控制)
│   ├── settings_store.py  # 系统设置读写(SETTING_SPECS + 60s TTL 缓存)
│   ├── email_utils.py     # SMTP 发送 / 告警 / 日报(失败仅记日志)
│   ├── async_utils.py     # enqueue():RQ 入队,失败自动同步降级
│   ├── realtime.py        # SSE:Redis pub/sub 发布/订阅/流生成器
│   ├── threat_intel.py    # 威胁情报:Spamhaus feed 同步 + AbuseIPDB + 缓存查询
│   ├── alert_engine.py    # 告警规则评估引擎
│   ├── audit.py           # 操作审计写入
│   ├── export_utils.py    # CSV/JSON/Excel 导出
│   ├── jobs.py            # RQ 任务(GeoIP/告警/威胁情报) + 定时调度器入口
│   ├── tasks.py           # 每日报告 / 过期数据清理
│   └── blueprints/
│       ├── auth.py        # 登录 / 登出 / 注册 / 忘记&重置密码
│       ├── admin.py       # 后台全部页面(/admin/*,含 /stream SSE 与用户管理)
│       ├── api.py         # /api/capture + 节点注册/心跳
│       └── settings.py    # 个人设置 + 系统设置(/admin/system-settings)
├── honeypots/             # 独立蜜罐程序(不依赖 app 包)
│   ├── http_honeypot.py   # HTTP 诱饵 + 签名上报 + 心跳 + 攻击检测
│   ├── ssh_honeypot.py    # SSH 假 shell(paramiko)
│   ├── telnet_honeypot.py # Telnet Cisco 风格假交互
│   ├── redis_honeypot.py  # Redis RESP 伪造响应
│   └── templates/         # phpMyAdmin / WordPress / 通用后台伪装页
├── templates/             # Jinja2 模板(含 users.html 用户管理、errors/、email/)
├── static/                # all.css 双主题样式 + echarts.min.js + world.json(本地化)
├── migrations/            # Alembic 迁移(0002~0008:黑名单/设置/节点/.../用户角色/威胁情报)
├── tests/                 # pytest(test_core + test_p3_features + test_p4_features,125 用例)
├── config.py              # 配置(环境变量:MySQL/Redis/SMTP/RQ/GEOIP/THREAT_INTEL)
├── manage.py              # 建表 / 创建管理员脚本
├── entrypoint.sh          # 容器启动脚本(迁移后 exec "$@",各服务命令可覆盖)
├── Dockerfile
├── docker-compose.yml     # 10 服务编排(含 4 类蜜罐)
└── nginx.conf             # Nginx 完整配置(含 /admin/stream SSE 无缓冲转发)
```

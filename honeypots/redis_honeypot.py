"""独立 Redis 蜜罐服务(纯 socket,实现 RESP 协议子集)。

模拟未授权访问的 Redis 实例,响应常见命令(INFO/CONFIG/SET/GET 等)返回伪造数据,
记录全部命令,识别写公钥/主从复制 RCE 等高危利用并上报。绝不执行真实 Redis 命令,
绝不写入磁盘或加载模块。

环境变量:
  HONEYPOT_API_URL       平台基础地址,默认 http://app:5000
  HONEYPOT_API_SECRET    HMAC 密钥(回退 API_SECRET_KEY)
  HONEYPOT_NODE_NAME     节点名,默认 redis-honeypot
  HONEYPOT_REDIS_PORT    监听端口,默认 6379
  HONEYPOT_REDIS_BIND    监听地址,默认 0.0.0.0
"""
import logging
import os
import socket
import threading

from ._reporter import PlatformReporter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [redis-honeypot] %(levelname)s %(message)s',
)
log = logging.getLogger('redis_honeypot')

API_URL = os.getenv('HONEYPOT_API_URL', 'http://app:5000').rstrip('/')
API_SECRET = os.getenv('HONEYPOT_API_SECRET') or os.getenv('API_SECRET_KEY', '')
NODE_NAME = os.getenv('HONEYPOT_NODE_NAME', 'redis-honeypot')
BIND = os.getenv('HONEYPOT_REDIS_BIND', '0.0.0.0')
PORT = int(os.getenv('HONEYPOT_REDIS_PORT', '6379'))

# 高危利用特征:CONFIG SET 写公钥/目录、主从复制 RCE、模块加载、调试命令
EXPLOIT_KEYWORDS = (
    'ssh-rsa', 'authorized_keys', 'slaveof', 'replicaof',
    'module load', 'module loadex', 'debug', 'eval',
    'config set dir', 'config set dbfilename', 'config set requirepass',
)

INFO_RESPONSE = (
    "# Server\r\n"
    "redis_version:5.0.7\r\n"
    "redis_git_sha1:00000000\r\n"
    "redis_git_dirty:0\r\n"
    "redis_build_id:636f5c05e1b2d3a4\r\n"
    "redis_mode:standalone\r\n"
    "os:Linux 5.4.0-42-generic x86_64\r\n"
    "arch_bits:64\r\n"
    "multiplexing_api:epoll\r\n"
    "atomicvar_api:atomic-builtin\r\n"
    "gcc_version:9.3.0\r\n"
    "process_id:1\r\n"
    "run_id:b7e1c2a3d4f5061728394a5b6c7d8e9f0a1b2c3d\r\n"
    "tcp_port:6379\r\n"
    "uptime_in_seconds:1037482\r\n"
    "uptime_in_days:12\r\n"
    "hz:10\r\n"
    "lru_clock:14253617\r\n"
    "config_file:/etc/redis/redis.conf\r\n"
    "# Clients\r\n"
    "connected_clients:1\r\n"
    "blocked_clients:0\r\n"
    "# Memory\r\n"
    "used_memory:851984\r\n"
    "used_memory_human:832.01K\r\n"
    "# Persistence\r\n"
    "loading:0\r\n"
    "rdb_last_bgsave_status:ok\r\n"
    "# Stats\r\n"
    "total_connections_received:42\r\n"
    "total_commands_processed:128\r\n"
    "# Replication\r\n"
    "role:master\r\n"
    "connected_slaves:0\r\n"
)


class RESPReader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b''

    def _recv_until(self, sep):
        while sep not in self.buf:
            data = self.sock.recv(4096)
            if not data:
                return None
            self.buf += data
        idx = self.buf.index(sep)
        line = self.buf[:idx]
        self.buf = self.buf[idx + len(sep):]
        return line

    def read_command(self):
        """读一条 RESP 命令,返回参数列表(均为 str)或 None(连接断开)。"""
        line = self._recv_until(b'\r\n')
        if line is None:
            return None
        line = line.strip()
        if not line:
            return []
        # 内联命令:裸文本(部分客户端/扫描器会发 `INFO\r\n`)
        if not line.startswith(b'*'):
            # 可能是空格分隔的内联命令
            try:
                return [line.decode('utf-8', errors='replace')]
            except Exception:
                return []
        try:
            count = int(line[1:])
        except ValueError:
            return []
        args = []
        for _ in range(count):
            head = self._recv_until(b'\r\n')
            if head is None:
                return None
            head = head.strip()
            if not head.startswith(b'$'):
                return args
            try:
                length = int(head[1:])
            except ValueError:
                return args
            if length < 0:
                args.append(None)
                continue
            while len(self.buf) < length + 2:
                data = self.sock.recv(4096)
                if not data:
                    return args
            arg = self.buf[:length].decode('utf-8', errors='replace')
            self.buf = self.buf[length + 2:]
            args.append(arg)
        return args


def _encode_simple(value):
    return f'+{value}\r\n'.encode()


def _encode_error(msg):
    return f'-ERR {msg}\r\n'.encode()


def _encode_bulk(value):
    if value is None:
        return b'$-1\r\n'
    data = value.encode() if isinstance(value, str) else value
    return f'${len(data)}\r\n'.encode() + data + b'\r\n'


def _encode_integer(value):
    return f':{value}\r\n'.encode()


def _encode_array(items):
    out = f'*{len(items)}\r\n'.encode()
    for item in items:
        if isinstance(item, bytes):
            out += _encode_bulk(item)
        else:
            out += _encode_bulk(item)
    return out


def detect_signature(command_str):
    cmd_lower = command_str.lower()
    for kw in EXPLOIT_KEYWORDS:
        if kw in cmd_lower:
            # 主从复制/模块加载是 RCE 级别
            if any(k in cmd_lower for k in ('slaveof', 'replicaof', 'module load', 'debug')):
                return 'redis_rce_attempt', 'critical'
            return 'redis_exploit_attempt', 'high'
    if cmd_lower.startswith(('info', 'ping', 'command', 'hello')):
        return 'redis_unauthorized', 'low'
    return 'redis_command', 'info'


class RedisConnection:
    def __init__(self, sock, client_ip, reporter):
        self.sock = sock
        self.client_ip = client_ip
        self.reporter = reporter
        self.commands = []

    def send(self, data):
        try:
            self.sock.sendall(data)
        except Exception:
            pass

    def handle_command(self, args):
        if not args:
            return
        cmd = (args[0] or '').lower()
        cmd_str = ' '.join(args)
        self.commands.append(cmd_str)

        # 基础命令伪造响应
        if cmd == 'ping':
            self.send(_encode_simple('PONG'))
        elif cmd == 'echo':
            self.send(_encode_bulk(args[1] if len(args) > 1 else ''))
        elif cmd == 'info':
            self.send(_encode_bulk(INFO_RESPONSE))
        elif cmd == 'command':
            self.send(_encode_array([]))
        elif cmd == 'hello':
            self.send(_encode_array([
                'server', 'redis', 'version', '5.0.7',
                'proto', 2, 'id', 1, 'mode', 'standalone',
                'role', 'master', 'modules', [],
            ]))
        elif cmd in ('set', 'setnx', 'setex'):
            self.send(_encode_simple('OK'))
        elif cmd in ('get', 'getset', 'type', 'ttl', 'pttl', 'object'):
            self.send(_encode_bulk(None))
        elif cmd in ('exists', 'del', 'unlink', 'expire', 'pexpire', 'persist'):
            self.send(_encode_integer(0))
        elif cmd in ('keys', 'smembers', 'lrange', 'hgetall', 'zrange'):
            self.send(_encode_array([]))
        elif cmd in ('dbsize', 'llen', 'scard', 'hlen', 'zcard'):
            self.send(_encode_integer(0))
        elif cmd in ('flushall', 'flushdb'):
            self.send(_encode_simple('OK'))
        elif cmd == 'config':
            sub = (args[1].lower() if len(args) > 1 else '')
            if sub == 'get':
                key = args[2] if len(args) > 2 else '*'
                self.send(_encode_array([key, '/var/lib/redis' if 'dir' in key else '']))
            elif sub == 'set':
                # 伪装成功,诱导攻击者继续(实际不做任何事)
                self.send(_encode_simple('OK'))
            elif sub == 'rewrite':
                self.send(_encode_simple('OK'))
            else:
                self.send(_encode_array([]))
        elif cmd in ('slaveof', 'replicaof'):
            self.send(_encode_simple('OK'))
        elif cmd == 'auth':
            # 未授权蜜罐:任何密码都接受,更像真开放实例
            self.send(_encode_simple('OK'))
        elif cmd == 'quit':
            self.send(_encode_simple('OK'))
            return False
        else:
            self.send(_encode_error(f"unknown command '{args[0]}'"))
        return True

    def run(self):
        reader = RESPReader(self.sock)
        while True:
            args = reader.read_command()
            if args is None:
                break
            cont = self.handle_command(args)
            if cont is False:
                break
            # 每 5 条或含高危命令立即上报
            sig, sev = detect_signature(' '.join(args))
            if sev in ('high', 'critical') or len(self.commands) >= 5:
                self.reporter.report({
                    'service': 'redis',
                    'honeypot_type': 'redis',
                    'signature': sig,
                    'severity': sev,
                    'client_ip': self.client_ip,
                    'payload': {'commands': self.commands[:]},
                })
                self.commands = []
        if self.commands:
            sig, sev = detect_signature(' '.join(self.commands))
            self.reporter.report({
                'service': 'redis',
                'honeypot_type': 'redis',
                'signature': sig,
                'severity': sev,
                'client_ip': self.client_ip,
                'payload': {'commands': self.commands},
            })


def _handle_client(sock, client_ip, reporter):
    try:
        conn = RedisConnection(sock, client_ip, reporter)
        conn.run()
    except Exception as e:
        log.debug('Redis 会话异常 %s: %s', client_ip, e)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    if not API_SECRET:
        log.warning('API_SECRET_KEY 未配置,攻击数据将无法通过平台鉴权')
    reporter = PlatformReporter(API_URL, API_SECRET, NODE_NAME, 'redis')
    reporter.register()
    reporter.start_heartbeat()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((BIND, PORT))
    server_sock.listen(128)
    log.info('Redis 蜜罐监听 %s:%d,节点名 %s', BIND, PORT, NODE_NAME)
    try:
        while True:
            try:
                client_sock, addr = server_sock.accept()
            except KeyboardInterrupt:
                break
            threading.Thread(
                target=_handle_client,
                args=(client_sock, addr[0], reporter),
                daemon=True,
            ).start()
    finally:
        server_sock.close()
        reporter.stop()


if __name__ == '__main__':
    main()

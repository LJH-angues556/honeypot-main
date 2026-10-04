"""独立 SSH 蜜罐服务(基于 Paramiko)。

模拟 Linux SSH 服务,捕获暴力破解的用户名/密码,登录成功后提供假 shell,
记录攻击者执行的全部命令(绝不真正执行),并异步上报到主平台。

环境变量:
  HONEYPOT_API_URL       平台基础地址,默认 http://app:5000
  HONEYPOT_API_SECRET    HMAC 密钥(回退 API_SECRET_KEY)
  HONEYPOT_NODE_NAME     节点名,默认 ssh-honeypot
  HONEYPOT_SSH_PORT      监听端口,默认 2222
  HONEYPOT_SSH_BIND      监听地址,默认 0.0.0.0
  HONEYPOT_SSH_ACCEPT_ANY  任意密码都"登录成功"(诱导进入假 shell),默认 true
  HONEYPOT_SSH_HOST_KEY  主机密钥文件路径;为空时内存生成 RSA 2048 临时密钥
"""
import logging
import os
import socket
import threading

import paramiko

from ._reporter import PlatformReporter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [ssh-honeypot] %(levelname)s %(message)s',
)
log = logging.getLogger('ssh_honeypot')

API_URL = os.getenv('HONEYPOT_API_URL', 'http://app:5000').rstrip('/')
API_SECRET = os.getenv('HONEYPOT_API_SECRET') or os.getenv('API_SECRET_KEY', '')
NODE_NAME = os.getenv('HONEYPOT_NODE_NAME', 'ssh-honeypot')
BIND = os.getenv('HONEYPOT_SSH_BIND', '0.0.0.0')
PORT = int(os.getenv('HONEYPOT_SSH_PORT', '2222'))
ACCEPT_ANY = os.getenv('HONEYPOT_SSH_ACCEPT_ANY', 'true').lower() in ('1', 'true', 'yes')
HOST_KEY_PATH = os.getenv('HONEYPOT_SSH_HOST_KEY', '')

BANNER = (
    "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
    "\r\n"
    " * Documentation:  https://help.ubuntu.com\r\n"
    " * Management:     https://landscape.canonical.com\r\n"
    " * Support:        https://ubuntu.com/advantage\r\n"
    "\r\n"
    "Last login: Mon Oct  2 03:14:07 2026 from 192.168.1.10\r\n\r\n"
)

# 假 shell 命令响应表;未列出的命令统一返回 "command not found",绝不真实执行
FAKE_COMMANDS = {
    'whoami': 'root\r\n',
    'id': 'uid=0(root) gid=0(root) groups=0(root)\r\n',
    'uname': 'Linux\r\n',
    'uname -a': ('Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP '
                 'Tue Nov 14 13:05:49 UTC 2023 x86_64 GNU/Linux\r\n'),
    'pwd': '/root\r\n',
    'hostname': 'ubuntu-22-04\r\n',
    'ls': 'Desktop  Documents  Downloads  .bashrc  .profile\r\n',
    'ls -la': ('total 32\r\n'
               'drwxr-xr-x  5 root root 4096 Oct  2 03:14 .\r\n'
               'drwxr-xr-x 19 root root 4096 Oct  2 03:14 ..\r\n'
               '-rw-r--r--  1 root root 3771 Oct  2 03:14 .bashrc\r\n'
               'drwxr-xr-x  2 root root 4096 Oct  2 03:14 Desktop\r\n'),
    'cat /etc/passwd': (
        'root:x:0:0:root:/root:/bin/bash\r\n'
        'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n'
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n'
        'ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\r\n'
    ),
    'cat /etc/os-release': (
        'NAME="Ubuntu"\r\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\r\n'
        'ID=ubuntu\r\nPRETTY_NAME="Ubuntu 22.04.3 LTS"\r\n'
    ),
    'date': 'Mon Oct  2 03:14:07 UTC 2026\r\n',
    'uptime': ' 03:14:07 up 12 days,  4:32,  1 user,  load average: 0.01, 0.05, 0.09\r\n',
    'free -m': ('              total        used        free      shared  buff/cache   available\r\n'
                'Mem:           1981         412         981          12         587        1425\r\n'
                'Swap:             0           0           0\r\n'),
    'ifconfig': ('eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n'
                 '        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255\r\n'),
}


class FakeServer(paramiko.ServerInterface):
    def __init__(self, client_ip, reporter):
        self.client_ip = client_ip
        self.reporter = reporter
        self.username = None
        self.password = None
        self.auth_ok = False

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        # 无论对错都上报一次登录尝试
        accepted = ACCEPT_ANY or (username == 'root' and password == 'root')
        sig = 'ssh_login_attempt' if not accepted else 'ssh_login_success'
        self.reporter.report({
            'service': 'ssh',
            'honeypot_type': 'ssh',
            'signature': sig,
            'severity': 'medium' if accepted else 'low',
            'client_ip': self.client_ip,
            'payload': {'username': username, 'password': password, 'accepted': accepted},
        })
        if accepted:
            self.auth_ok = True
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        # 登录成功后由 FakeShell 接管通道
        return True


def _fake_shell(channel, server):
    """假 shell 循环:读命令、查表响应、上报,绝不真实执行。"""
    commands = []
    channel.send(BANNER)
    while True:
        channel.send('root@ubuntu-22-04:~# ')
        line = b''
        try:
            while not line.endswith(b'\n') and not line.endswith(b'\r'):
                chunk = channel.recv(1024)
                if not chunk:
                    return
                line += chunk
                # 回显输入字符(让攻击者感觉像真终端),忽略控制字符
                if chunk in (b'\x7f', b'\x08'):
                    channel.send(b'\b \b')
                elif chunk in (b'\r', b'\n'):
                    channel.send(b'\r\n')
                elif chunk not in (b'\x03', b'\x04'):
                    channel.send(chunk)
        except Exception:
            return
        cmd = line.decode(errors='ignore').strip()
        if not cmd:
            continue
        if cmd in ('exit', 'logout', 'quit'):
            channel.send('logout\r\n')
            break
        if cmd == '\x03':  # Ctrl-C
            channel.send('^C\r\n')
            continue
        commands.append(cmd)
        response = FAKE_COMMANDS.get(cmd)
        if response is None:
            # 危险命令(反弹shell/下载执行)一律伪装失败,绝不真实执行
            if cmd.startswith(('wget ', 'curl ', 'bash ', 'sh ', 'chmod +x',
                               'nc ', 'python', 'perl')):
                response = (f'-bash: {cmd.split()[0]}: command not found\r\n')
            else:
                response = f'-bash: {cmd.split()[0]}: command not found\r\n'
        channel.send(response)
        # 每 5 条命令上报一次,避免高频请求
        if len(commands) >= 5:
            server.reporter.report({
                'service': 'ssh',
                'honeypot_type': 'ssh',
                'signature': 'ssh_command',
                'severity': 'medium',
                'client_ip': server.client_ip,
                'payload': {'username': server.username, 'commands': commands[:]},
            })
            commands = []
    if commands:
        server.reporter.report({
            'service': 'ssh',
            'honeypot_type': 'ssh',
            'signature': 'ssh_command',
            'severity': 'medium',
            'client_ip': server.client_ip,
            'payload': {'username': server.username, 'commands': commands},
        })


def _handle_client(sock, client_ip, reporter, host_key):
    try:
        transport = paramiko.Transport(sock)
        transport.add_server_key(host_key)
        server = FakeServer(client_ip, reporter)
        transport.start_server(server=server)
        chan = transport.accept(timeout=20)
        if chan is None:
            transport.close()
            return
        if server.auth_ok:
            _fake_shell(chan, server)
        chan.close()
    except Exception as e:
        log.debug('SSH 会话异常 %s: %s', client_ip, e)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    if not API_SECRET:
        log.warning('API_SECRET_KEY 未配置,攻击数据将无法通过平台鉴权')

    # 主机密钥:优先读文件,否则内存生成(容器每次重建密钥会变,客户端会警告更像真蜜罐)
    if HOST_KEY_PATH and os.path.exists(HOST_KEY_PATH):
        host_key = paramiko.RSAKey.from_private_key_file(HOST_KEY_PATH)
    else:
        log.info('未指定主机密钥文件,内存生成临时 RSA-2048 密钥')
        host_key = paramiko.RSAKey.generate(2048)

    reporter = PlatformReporter(API_URL, API_SECRET, NODE_NAME, 'ssh')
    reporter.register()
    reporter.start_heartbeat()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((BIND, PORT))
    server_sock.listen(128)
    log.info('SSH 蜜罐监听 %s:%d (accept_any=%s),节点名 %s',
             BIND, PORT, ACCEPT_ANY, NODE_NAME)
    try:
        while True:
            try:
                client_sock, addr = server_sock.accept()
            except KeyboardInterrupt:
                break
            client_ip = addr[0]
            t = threading.Thread(
                target=_handle_client,
                args=(client_sock, client_ip, reporter, host_key),
                daemon=True,
            )
            t.start()
    finally:
        server_sock.close()
        reporter.stop()


if __name__ == '__main__':
    main()

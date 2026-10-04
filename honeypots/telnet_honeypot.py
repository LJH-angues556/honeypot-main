"""独立 Telnet 蜜罐服务(纯 socket,无外部依赖)。

模拟路由器/老式 Unix 的 Telnet 登录界面,捕获用户名/密码,登录成功后提供假 shell,
记录全部命令并异步上报。绝不真实执行任何命令。

环境变量:
  HONEYPOT_API_URL       平台基础地址,默认 http://app:5000
  HONEYPOT_API_SECRET    HMAC 密钥(回退 API_SECRET_KEY)
  HONEYPOT_NODE_NAME     节点名,默认 telnet-honeypot
  HONEYPOT_TELNET_PORT   监听端口,默认 2323
  HONEYPOT_TELNET_BIND   监听地址,默认 0.0.0.0
  HONEYPOT_TELNET_BANNER 登录前横幅,默认 Cisco 风格
"""
import logging
import os
import socket
import threading

from ._reporter import PlatformReporter

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [telnet-honeypot] %(levelname)s %(message)s',
)
log = logging.getLogger('telnet_honeypot')

API_URL = os.getenv('HONEYPOT_API_URL', 'http://app:5000').rstrip('/')
API_SECRET = os.getenv('HONEYPOT_API_SECRET') or os.getenv('API_SECRET_KEY', '')
NODE_NAME = os.getenv('HONEYPOT_NODE_NAME', 'telnet-honeypot')
BIND = os.getenv('HONEYPOT_TELNET_BIND', '0.0.0.0')
PORT = int(os.getenv('HONEYPOT_TELNET_PORT', '2323'))
BANNER = os.getenv('HONEYPOT_TELNET_BANNER',
                   '\r\nCisco IOS Software, C2960 Software (C2960-LANBASEK9-M), '
                   'Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)\r\n'
                   'Copyright (c) 1986-2018 by Cisco Systems, Inc.\r\n\r\n')

# Telnet 协议常量
IAC = 255
DO, DONT, WILL, WONT = 253, 254, 251, 252
ECHO = 1
SGA = 3  # Suppress Go Ahead

MOTD = (
    '\r\nCisco IOS Software, C2960 Software (C2960-LANBASEK9-M)\r\n'
    'Last login: Mon Oct  2 03:14:07 on vty0\r\n\r\n'
)

# 假 shell 响应
FAKE_CMDS = {
    'enable': 'Password: \r\n% Invalid input detected at \'^\' marker.\r\n',
    'show version': (
        'Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), '
        'Version 15.0(2)SE11\r\n'
        'ROM: Bootstrap program is C2960 boot loader\r\n'
        'cisco-2960 uptime is 12 weeks, 4 days, 3 hours, 14 minutes\r\n'
    ),
    'show interfaces': (
        'FastEthernet0/1 is up, line protocol is up\r\n'
        '  Hardware is Fast Ethernet, address is 001b.d4a1.2c34 (bia 001b.d4a1.2c34)\r\n'
    ),
    'show running-config': 'Building configuration...\r\n\r\nCurrent configuration : 2048 bytes\r\n!\r\n',
    'show ip interface brief': (
        'Interface              IP-Address      OK? Method Status                Protocol\r\n'
        'Vlan1                  192.168.1.1     YES NVRAM  up                    up      \r\n'
        'FastEthernet0/1        unassigned      YES unset  up                    up      \r\n'
    ),
    'ping 8.8.8.8': 'Type escape sequence to abort.\r\nSending 5, 100-byte ICMP Echos to 8.8.8.8\r\n.....\r\nSuccess rate is 0 percent (0/5)\r\n',
    '?': (
        'Exec commands:\r\n'
        '  enable    Turn on privileged commands\r\n'
        '  show      Show running system information\r\n'
        '  ping      Send echo messages\r\n'
        '  exit      Exit from EXEC mode\r\n'
    ),
}


class TelnetConnection:
    def __init__(self, sock, client_ip, reporter):
        self.sock = sock
        self.client_ip = client_ip
        self.reporter = reporter
        self.username = None

    def send(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8', errors='replace')
        try:
            self.sock.sendall(data)
        except Exception:
            pass

    def read_line(self, echo=True, mask=False):
        """读一行,处理 IAC 协商;mask=True 时不回显(密码输入)。"""
        buf = b''
        while True:
            try:
                data = self.sock.recv(1024)
            except Exception:
                return buf.decode(errors='ignore')
            if not data:
                return buf.decode(errors='ignore')
            i = 0
            while i < len(data):
                byte = data[i]
                if byte == IAC and i + 1 < len(data):
                    cmd = data[i + 1]
                    if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(data):
                        opt = data[i + 2]
                        # 拒绝客户端要求的所有能力,客户端会退回半双工行模式
                        if cmd == DO:
                            self.sock.sendall(bytes([IAC, WONT, opt]))
                        elif cmd == WILL:
                            self.sock.sendall(bytes([IAC, DONT, opt]))
                        i += 3
                        continue
                    elif cmd == IAC:  # 转义的 0xFF
                        buf += bytes([IAC])
                        i += 2
                        continue
                    else:
                        i += 2
                        continue
                elif byte in (13, 10):  # CR / LF
                    self.send(b'\r\n')
                    return buf.decode(errors='ignore')
                elif byte in (127, 8):  # Backspace
                    if buf:
                        buf = buf[:-1]
                        self.send(b'\b \b')
                elif byte == 3:  # Ctrl-C
                    self.send(b'\r\n')
                    return '__INTERRUPT__'
                else:
                    buf += bytes([byte])
                    if echo:
                        if mask:
                            self.send(b'*')
                        else:
                            self.send(bytes([byte]))
                i += 1

    def run(self):
        self.send(BANNER)
        self.send(b'\r\nUser Access Verification\r\n\r\n')
        self.send(b'Username: ')
        username = self.read_line()
        if username == '__INTERRUPT__' or not username:
            return
        self.username = username
        self.send(b'Password: ')
        password = self.read_line(echo=True, mask=True)
        if password == '__INTERRUPT__':
            return
        # 上报登录尝试(任意凭据都"成功",诱导进入假 shell)
        self.reporter.report({
            'service': 'telnet',
            'honeypot_type': 'telnet',
            'signature': 'telnet_login_attempt',
            'severity': 'medium',
            'client_ip': self.client_ip,
            'payload': {'username': username, 'password': password},
        })
        self.send(MOTD)
        self._fake_shell()

    def _fake_shell(self):
        commands = []
        while True:
            self.send('cisco-2960> ')
            cmd = self.read_line()
            if cmd == '__INTERRUPT__':
                break
            cmd = cmd.strip()
            if not cmd:
                continue
            if cmd in ('exit', 'logout', 'quit', 'q'):
                self.send('\r\n')
                break
            commands.append(cmd)
            response = FAKE_CMDS.get(cmd)
            if response is None:
                if cmd.startswith(('enable',)):
                    response = FAKE_CMDS['enable']
                else:
                    response = (f'% Invalid input detected at \'^\' marker.\r\n'
                                f'% {cmd.split()[0] if cmd.split() else ""}'
                                f' is an invalid command.\r\n')
            self.send(response)
            if len(commands) >= 5:
                self.reporter.report({
                    'service': 'telnet',
                    'honeypot_type': 'telnet',
                    'signature': 'telnet_command',
                    'severity': 'medium',
                    'client_ip': self.client_ip,
                    'payload': {'username': self.username, 'commands': commands[:]},
                })
                commands = []
        if commands:
            self.reporter.report({
                'service': 'telnet',
                'honeypot_type': 'telnet',
                'signature': 'telnet_command',
                'severity': 'medium',
                'client_ip': self.client_ip,
                'payload': {'username': self.username, 'commands': commands},
            })


def _handle_client(sock, client_ip, reporter):
    try:
        conn = TelnetConnection(sock, client_ip, reporter)
        conn.run()
    except Exception as e:
        log.debug('Telnet 会话异常 %s: %s', client_ip, e)
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    if not API_SECRET:
        log.warning('API_SECRET_KEY 未配置,攻击数据将无法通过平台鉴权')
    reporter = PlatformReporter(API_URL, API_SECRET, NODE_NAME, 'telnet')
    reporter.register()
    reporter.start_heartbeat()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((BIND, PORT))
    server_sock.listen(128)
    log.info('Telnet 蜜罐监听 %s:%d,节点名 %s', BIND, PORT, NODE_NAME)
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

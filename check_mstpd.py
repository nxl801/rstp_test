#!/usr/bin/env python3
import sys
sys.path.append('.')
from src.ssh_manager import SSHManager
import yaml
import time

# 读取配置
with open('config.yaml', 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

# 创建SSH连接
node_config = config['vms']['nodes'][0]
ssh = SSHManager(
    name=node_config['name'],
    ip=node_config['ip'],
    username=node_config['username'],
    password=node_config['password'],
    port=node_config.get('port', 22)
)
ssh.connect()

print('=== 检查mstpd服务状态 ===')
stdout, stderr, code = ssh.execute('sudo systemctl status mstpd')
print(f'mstpd状态: code={code}')
print(f'stdout: {stdout[:500]}')
print(f'stderr: {stderr}')

print('\n=== 检查是否有桥存在 ===')
stdout, stderr, code = ssh.execute('brctl show')
print(f'brctl show: {stdout}')

print('\n=== 尝试创建测试桥 ===')
ssh.execute_sudo('brctl delbr test_br 2>/dev/null || true')
stdout, stderr, code = ssh.execute_sudo('brctl addbr test_br')
print(f'创建桥: code={code}, stderr={stderr}')

stdout, stderr, code = ssh.execute_sudo('brctl stp test_br on')
print(f'启用STP: code={code}, stderr={stderr}')

stdout, stderr, code = ssh.execute_sudo('ip link set dev test_br up')
print(f'启动桥: code={code}, stderr={stderr}')

time.sleep(2)

print('\n=== 测试mstpd配置 ===')
stdout, stderr, code = ssh.execute_sudo('mstpctl setforcevers test_br rstp')
print(f'设置RSTP: code={code}, stderr={stderr}')

stdout, stderr, code = ssh.execute_sudo('mstpctl setbridgeprio test_br 4096')
print(f'设置优先级: code={code}, stderr={stderr}')

stdout, stderr, code = ssh.execute_sudo('mstpctl setbridgehello test_br 2')
print(f'设置Hello: code={code}, stderr={stderr}')

stdout, stderr, code = ssh.execute_sudo('mstpctl setbridgefdelay test_br 15')
print(f'设置Forward Delay: code={code}, stderr={stderr}')

stdout, stderr, code = ssh.execute_sudo('mstpctl setbridgemaxage test_br 20')
print(f'设置Max Age: code={code}, stderr={stderr}')

print('\n=== 验证配置 ===')
stdout, stderr, code = ssh.execute_sudo('mstpctl showbridge test_br')
print(f'showbridge: code={code}')
print(f'输出: {stdout}')
print(f'错误: {stderr}')

# 清理
ssh.execute_sudo('brctl delbr test_br')
ssh.close()
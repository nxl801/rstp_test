#!/usr/bin/env python3
"""
调试BPDU注入功能的独立测试脚本
"""

import sys
import os
import yaml
from pathlib import Path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from ssh_manager import SSHManager
from fault_injector import FaultInjector
import time

def load_config():
    """加载配置文件"""
    config_path = Path(__file__).parent / "config.yaml"
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def test_bpdu_injection():
    """测试BPDU注入功能"""
    print("=== 调试BPDU注入功能 ===")
    
    # 加载配置
    config = load_config()
    
    # 查找TestNode1配置
    testnode1_config = None
    for node_config in config['vms']['nodes']:
        if node_config['name'] == 'TestNode1':
            testnode1_config = node_config
            break
    
    if not testnode1_config:
        print("错误: 未找到TestNode1配置")
        return False
    
    # 连接到TestNode1
    testnode1 = SSHManager(
        name=testnode1_config['name'],
        ip=testnode1_config['ip'],
        username=testnode1_config['username'],
        password=testnode1_config['password']
    )
    
    if not testnode1.connect():
        print("错误: 无法连接到TestNode1")
        return False
    
    if not testnode1:
        print("错误: 无法连接到TestNode1")
        return False
    
    # 创建故障注入器
    injector = FaultInjector(testnode1)
    
    print("\n1. 检查网络接口状态")
    stdout, stderr, code = testnode1.execute("ip link show")
    print(f"网络接口:\n{stdout}")
    
    print("\n2. 检查网桥配置")
    stdout, stderr, code = testnode1.execute("brctl show")
    print(f"网桥配置:\n{stdout}")
    
    print("\n3. 检查路由表")
    stdout, stderr, code = testnode1.execute("ip route")
    print(f"路由表:\n{stdout}")
    
    print("\n4. 测试到DUT的连通性")
    dut_ip = config['vms']['dut']['ip']  # 使用配置文件中的DUT IP
    print(f"DUT IP: {dut_ip}")
    stdout, stderr, code = testnode1.execute(f"ping -c 3 {dut_ip}")
    print(f"Ping DUT结果:\n{stdout}")
    if stderr:
        print(f"错误: {stderr}")
    
    print("\n5. 执行BPDU注入测试")
    print("注入参数: interface=eth2, priority=0, count=5")
    
    # 执行BPDU注入
    result = injector.inject_rogue_bpdu(
        interface="eth2",
        priority=0,
        src_mac="00:11:22:33:44:55",
        count=5,
        interval=1.0
    )
    
    print(f"\n6. BPDU注入结果: {'成功' if result else '失败'}")
    
    # 检查注入脚本是否存在
    print("\n7. 检查注入脚本")
    stdout, stderr, code = testnode1.execute("ls -la /tmp/rogue_bpdu_enhanced.py")
    if code == 0:
        print(f"脚本文件存在:\n{stdout}")
        
        # 查看脚本内容的前几行
        stdout, stderr, code = testnode1.execute("head -20 /tmp/rogue_bpdu_enhanced.py")
        print(f"\n脚本内容预览:\n{stdout}")
    else:
        print("脚本文件不存在")
    
    # 手动执行一个简单的scapy测试
    print("\n8. 手动执行简单的scapy测试")
    simple_test = '''
from scapy.all import *
import time

print("开始简单BPDU测试...")

try:
    # 构建简单的BPDU包
    eth = Ether(dst="01:80:c2:00:00:00", src="00:11:22:33:44:55")
    llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
    bpdu = STP(
        proto=0x0000,
        version=0x02,
        bpdutype=0x02,
        bpduflags=0x78,
        rootid=0,
        pathcost=0,
        bridgeid=0,
        portid=0x8001,
        maxage=20,
        hellotime=2,
        fwddelay=15
    )
    
    packet = eth/llc/bpdu
    print(f"包构建成功: {packet.summary()}")
    
    # 尝试从eth2发送
    sendp(packet, iface="eth2", verbose=1, count=1)
    print("BPDU发送完成")
    
except Exception as e:
    print(f"发送失败: {e}")
    import traceback
    traceback.print_exc()
'''
    
    # 写入简单测试脚本
    write_cmd = f"cat > /tmp/simple_bpdu_test.py << 'EOF'\n{simple_test}\nEOF"
    testnode1.execute(write_cmd)
    
    # 执行简单测试
    stdout, stderr, code = testnode1.execute_sudo("python3 /tmp/simple_bpdu_test.py")
    print(f"简单测试结果 (code={code}):")
    if stdout:
        print(f"STDOUT: {stdout}")
    if stderr:
        print(f"STDERR: {stderr}")
    
    print("\n=== 调试完成 ===")
    
    # 关闭连接
    testnode1.close()
    
    return result

if __name__ == "__main__":
    success = test_bpdu_injection()
    sys.exit(0 if success else 1)
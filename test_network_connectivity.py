#!/usr/bin/env python3
"""
测试网络连通性脚本
检查TestNode1的ens33接口是否能到达DUT
"""

import subprocess
import sys
import time
import yaml
from pathlib import Path
from src.ssh_manager import SSHManager

def load_config():
    """加载配置文件"""
    config_path = Path(__file__).parent / "config.yaml"
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def test_connectivity():
    """测试网络连通性"""
    print("=== 网络连通性测试 ===")
    
    # 加载配置
    config = load_config()
    
    # 连接TestNode1
    testnode1_config = None
    for node in config['vms']['nodes']:
        if node['name'] == 'TestNode1':
            testnode1_config = node
            break
    
    if not testnode1_config:
        print("✗ 未找到TestNode1配置")
        return False
    
    testnode1 = SSHManager(
        testnode1_config['name'],
        testnode1_config['ip'],
        testnode1_config['username'],
        testnode1_config['password']
    )
    
    try:
        testnode1.connect()
        print("✓ TestNode1 SSH连接成功")
        
        # 检查所有网络接口
        print("\n1. 检查TestNode1的所有网络接口:")
        stdout, stderr, code = testnode1.execute("ip link show")
        if code == 0:
            print(f"所有接口:\n{stdout}")
            # 查找可用的接口
            available_interfaces = []
            for line in stdout.split('\n'):
                if ': ' in line and 'lo:' not in line:
                    interface = line.split(':')[1].strip().split('@')[0]
                    available_interfaces.append(interface)
            print(f"可用接口: {available_interfaces}")
        else:
            print(f"✗ 无法获取接口列表: {stderr}")
            return False
            
        # 检查主要接口IP（通常是第一个非lo接口）
        main_interface = available_interfaces[0] if available_interfaces else None
        if main_interface:
            print(f"\n2. 检查{main_interface}接口IP:")
            stdout, stderr, code = testnode1.execute(f"ip addr show {main_interface}")
            if code == 0:
                print(f"{main_interface} IP信息:\n{stdout}")
        
        # 检查路由表
        print("\n3. 检查路由表:")
        stdout, stderr, code = testnode1.execute("ip route")
        if code == 0:
            print(f"路由表:\n{stdout}")
        
        # 尝试ping DUT
        print("\n4. 尝试ping DUT:")
        dut_ip = config['vms']['dut']['ip']
        stdout, stderr, code = testnode1.execute(f"ping -c 3 {dut_ip}")
        if code == 0:
            print(f"✓ 可以ping通DUT ({dut_ip})")
        else:
            print(f"✗ 无法ping通DUT ({dut_ip}): {stderr}")
        
        # 检查ARP表
        print("\n5. 检查ARP表:")
        stdout, stderr, code = testnode1.execute("arp -a")
        if code == 0:
            print(f"ARP表:\n{stdout}")
        
        # 测试发送简单的以太网帧到DUT
        if main_interface:
            print(f"\n6. 测试发送以太网帧到DUT（使用{main_interface}接口）:")
            test_script = f"""
from scapy.all import *
import time

# 发送简单的以太网帧
eth = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
arp_req = ARP(op=1, pdst="{dut_ip}")
packet = eth/arp_req

print("发送ARP请求到DUT...")
sendp(packet, iface="{main_interface}", verbose=1)
print("ARP请求已发送")
"""
            
            # 写入测试脚本
            testnode1.execute(f"echo '{test_script}' > /tmp/test_send.py")
            stdout, stderr, code = testnode1.execute("python3 /tmp/test_send.py")
            if code == 0:
                print(f"✓ 以太网帧发送成功: {stdout}")
            else:
                print(f"✗ 以太网帧发送失败: {stderr}")
        
        # 返回主要接口名称供后续使用
        return main_interface
        
        
    except Exception as e:
        print(f"✗ 连接失败: {e}")
        return None
    finally:
        testnode1.close()

def check_dut_interfaces():
    """检查DUT接口状态"""
    print("\n=== DUT接口状态检查 ===")
    
    config = load_config()
    dut = SSHManager(
        config['vms']['dut']['name'],
        config['vms']['dut']['ip'],
        config['vms']['dut']['username'],
        config['vms']['dut']['password']
    )
    
    try:
        dut.connect()
        print("✓ DUT SSH连接成功")
        
        # 检查网桥状态
        print("\n1. 检查SE_ETH2网桥状态:")
        stdout, stderr, code = dut.execute_as_root("brctl show SE_ETH2")
        if code == 0:
            print(f"SE_ETH2网桥状态:\n{stdout}")
        else:
            print(f"SE_ETH2网桥状态检查失败: {stderr}")
        
        # 检查br3和br4接口
        print("\n2. 检查br3和br4接口状态:")
        for iface in ['br3', 'br4']:
            stdout, stderr, code = dut.execute_as_root(f"ip link show {iface}")
            if code == 0:
                print(f"✓ {iface}接口: {stdout.strip()}")
            else:
                print(f"✗ {iface}接口不存在: {stderr}")
        
        # 检查接口统计
        print("\n3. 检查接口统计:")
        for iface in ['br3', 'br4']:
            stdout, stderr, code = dut.execute_as_root(f"cat /sys/class/net/{iface}/statistics/rx_packets")
            if code == 0:
                print(f"{iface} RX packets: {stdout.strip()}")
        
        return True
        
    except Exception as e:
        print(f"✗ DUT连接失败: {e}")
        return False
    finally:
        dut.close()

if __name__ == "__main__":
    print("开始网络连通性测试...")
    
    main_interface = test_connectivity()
    success2 = check_dut_interfaces()
    
    if main_interface and success2:
        print("\n=== 测试完成 ===")
        print(f"网络连通性测试通过，TestNode1的主要接口是: {main_interface}")
        print(f"建议修改BPDU注入接口为: {main_interface}")
    else:
        print("\n=== 测试失败 ===")
        print("网络连通性存在问题，需要修复网络配置")
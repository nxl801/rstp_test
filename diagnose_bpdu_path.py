#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
诊断BPDU传输路径
"""

import yaml
import time
from pathlib import Path
from src.ssh_manager import SSHManager

def load_config():
    """加载配置文件"""
    config_path = Path("config.yaml")
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def diagnose_bpdu_path():
    """诊断BPDU传输路径"""
    print("=== BPDU传输路径诊断 ===")
    
    # 加载配置
    config = load_config()
    
    # 查找TestNode1配置
    testnode1_config = None
    for node_config in config['vms']['nodes']:
        if node_config['name'] == 'TestNode1':
            testnode1_config = node_config
            break
    
    if not testnode1_config:
        print("✗ 未找到TestNode1配置")
        return False
    
    # 连接TestNode1和DUT
    testnode1 = SSHManager(
        testnode1_config['name'],
        testnode1_config['ip'],
        testnode1_config['username'],
        testnode1_config['password']
    )
    
    dut = SSHManager(
        config['vms']['dut']['name'],
        config['vms']['dut']['ip'],
        config['vms']['dut']['username'],
        config['vms']['dut']['password']
    )
    
    try:
        # 1. 检查TestNode1的eth2接口状态
        print("\n1. TestNode1 eth2接口详细状态:")
        stdout, _, _ = testnode1.execute("ip addr show eth2")
        print(stdout)
        
        # 2. 检查TestNode1的网桥配置
        print("\n2. TestNode1网桥配置:")
        stdout, _, _ = testnode1.execute("brctl show")
        print(stdout)
        
        # 3. 检查DUT的网络接口
        print("\n3. DUT网络接口状态:")
        stdout, _, _ = dut.execute("ip addr show | grep -A 5 'br[0-9]'")
        print(stdout)
        
        # 4. 在DUT上启动tcpdump监听BPDU
        print("\n4. 在DUT上启动BPDU监听...")
        dut.execute("pkill tcpdump")  # 停止之前的tcpdump
        time.sleep(1)
        
        # 启动tcpdump监听所有接口的BPDU
        dut.execute("nohup tcpdump -i any -w /tmp/bpdu_capture.pcap 'ether dst 01:80:c2:00:00:00' > /dev/null 2>&1 &")
        time.sleep(2)
        
        # 5. 从TestNode1发送测试BPDU
        print("\n5. 从TestNode1发送测试BPDU...")
        
        # 创建简单的BPDU发送脚本
        bpdu_script = '''
import socket
import struct
import time

# 创建RAW socket
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind(("eth2", 0))

# 构建BPDU帧
dst_mac = bytes.fromhex("0180c2000000")  # STP组播地址
src_mac = bytes.fromhex("001122334455")  # 源MAC
eth_type = struct.pack(">H", 0x8870)     # 长度字段

# LLC头
llc = bytes([0x42, 0x42, 0x03])  # DSAP=0x42, SSAP=0x42, Control=0x03

# STP BPDU
bpdu = bytes([
    0x00, 0x00,           # Protocol ID
    0x00,                 # Version
    0x00,                 # BPDU Type (Configuration)
    0x01,                 # Flags (Topology Change)
    0x00, 0x00,           # Root ID Priority (0)
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  # Root ID MAC
    0x00, 0x00, 0x00, 0x00,  # Root Path Cost
    0x00, 0x00,           # Bridge ID Priority (0)
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  # Bridge ID MAC
    0x80, 0x01,           # Port ID
    0x00, 0x00,           # Message Age
    0x00, 0x00,           # Max Age
    0x00, 0x00,           # Hello Time
    0x00, 0x00            # Forward Delay
])

# 组装完整帧
frame = dst_mac + src_mac + eth_type + llc + bpdu

print(f"发送BPDU帧，长度: {len(frame)} bytes")
for i in range(5):
    sock.send(frame)
    print(f"发送BPDU #{i+1}")
    time.sleep(1)

sock.close()
print("BPDU发送完成")
'''
        
        testnode1.execute(f"echo '{bpdu_script}' > /tmp/test_bpdu_raw.py")
        stdout, stderr, code = testnode1.execute_sudo("python3 /tmp/test_bpdu_raw.py")
        print(f"BPDU发送结果 (code={code}):")
        print(stdout)
        if stderr:
            print(f"错误: {stderr}")
        
        # 6. 等待并检查DUT上的抓包结果
        print("\n6. 等待5秒后检查DUT抓包结果...")
        time.sleep(5)
        
        # 停止tcpdump
        dut.execute("pkill tcpdump")
        time.sleep(1)
        
        # 分析抓包结果
        stdout, _, _ = dut.execute("tcpdump -r /tmp/bpdu_capture.pcap -c 10")
        print("DUT抓包结果:")
        print(stdout if stdout.strip() else "未捕获到任何BPDU")
        
        # 7. 检查网络路径
        print("\n7. 网络路径分析:")
        print("TestNode1 -> eth2 -> ??? -> DUT")
        
        # 检查TestNode1的ARP表
        stdout, _, _ = testnode1.execute("arp -a")
        print(f"TestNode1 ARP表: {stdout}")
        
        # 检查DUT的ARP表
        stdout, _, _ = dut.execute("arp -a")
        print(f"DUT ARP表: {stdout}")
        
        return True
        
    except Exception as e:
        print(f"诊断过程中出错: {e}")
        return False
    finally:
        testnode1.close()
        dut.close()

if __name__ == "__main__":
    diagnose_bpdu_path()
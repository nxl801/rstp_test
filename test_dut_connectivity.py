#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试TestNode1到DUT的连通性和BPDU传输
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

def main():
    print("=== TestNode1到DUT连通性测试 ===")
    
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
        return
    
    dut_ip = config['vms']['dut']['ip']
    print(f"DUT IP: {dut_ip}")
    print(f"TestNode1 IP: {testnode1_config['ip']}")
    
    # 连接TestNode1
    testnode1 = SSHManager(
        name=testnode1_config['name'],
        ip=testnode1_config['ip'],
        username=testnode1_config['username'],
        password=testnode1_config['password']
    )
    
    # 连接DUT
    dut = SSHManager(
        name=config['vms']['dut']['name'],
        ip=dut_ip,
        username=config['vms']['dut']['username'],
        password=config['vms']['dut']['password']
    )
    
    try:
        testnode1.connect()
        dut.connect()
        print("✓ SSH连接成功")
        
        # 1. 检查TestNode1的网络接口
        print("\n1. 检查TestNode1网络接口:")
        stdout, stderr, code = testnode1.execute("ip addr show")
        for line in stdout.split('\n'):
            if 'eth' in line and ('inet ' in line or 'UP' in line):
                print(f"  {line.strip()}")
        
        # 2. 检查DUT的网络接口
        print("\n2. 检查DUT网络接口:")
        stdout, stderr, code = dut.execute_sudo("ip addr show")
        for line in stdout.split('\n'):
            if ('br' in line or 'eth' in line) and ('inet ' in line or 'UP' in line):
                print(f"  {line.strip()}")
        
        # 3. 从TestNode1 ping DUT
        print("\n3. 连通性测试:")
        stdout, stderr, code = testnode1.execute(f"ping -c 3 {dut_ip}")
        if code == 0:
            print("✓ TestNode1可以ping通DUT")
        else:
            print("✗ TestNode1无法ping通DUT")
            print(f"错误: {stderr}")
        
        # 4. 检查DUT的OVS桥接配置
        print("\n4. 检查DUT的OVS桥接配置:")
        stdout, stderr, code = dut.execute_sudo("ovs-vsctl show")
        if code == 0:
            print("OVS配置:")
            print(stdout)
        else:
            print(f"获取OVS配置失败: {stderr}")
        
        # 5. 在DUT上启动抓包
        print("\n5. 在DUT上启动BPDU抓包...")
        # 先清理旧的抓包文件
        dut.execute_sudo("rm -f /tmp/test_bpdu_capture.pcap")
        
        # 启动抓包（捕获所有BPDU）
        dut.execute_sudo(
            "nohup tcpdump -i any -c 10 -w /tmp/test_bpdu_capture.pcap "
            "'ether dst 01:80:c2:00:00:00' > /tmp/tcpdump_test.log 2>&1 &"
        )
        time.sleep(2)
        
        # 6. 从TestNode1发送测试BPDU
        print("\n6. 从TestNode1发送测试BPDU...")
        bpdu_script = '''
#!/usr/bin/env python3
from scapy.all import *
import time

print("开始发送测试BPDU...")

# 尝试所有可能的接口
interfaces = ["eth0", "eth1", "eth2"]

for iface in interfaces:
    try:
        print(f"尝试接口: {iface}")
        
        # 构建BPDU包
        eth = Ether(dst="01:80:c2:00:00:00", src="00:11:22:33:44:55")
        llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
        
        # Rapid STP BPDU
        bpdu = STP(
            bpdutype=0x02,  # Rapid STP类型
            bpduflags=0x3C,  # RSTP标准标志位
            rootid=0,
            rootmac="00:11:22:33:44:55",
            pathcost=0,
            bridgeid=0,
            bridgemac="00:11:22:33:44:55",
            portid=0x8001,
            maxage=20,
            hellotime=2,
            fwddelay=15
        )
        
        packet = eth/llc/bpdu
        
        # 发送3个BPDU包
        for i in range(3):
            sendp(packet, iface=iface, verbose=0)
            print(f"  发送BPDU #{i+1} 到 {iface}")
            time.sleep(1)
            
    except Exception as e:
        print(f"  接口 {iface} 发送失败: {e}")

print("BPDU发送完成")
'''
        
        # 写入并执行脚本
        testnode1.execute(f"echo '{bpdu_script}' > /tmp/test_bpdu_send.py")
        testnode1.execute("chmod +x /tmp/test_bpdu_send.py")
        stdout, stderr, code = testnode1.execute_sudo("python3 /tmp/test_bpdu_send.py")
        print("BPDU发送结果:")
        print(stdout)
        if stderr:
            print(f"错误: {stderr}")
        
        # 等待抓包完成
        time.sleep(5)
        
        # 7. 分析抓包结果
        print("\n7. 分析DUT抓包结果:")
        # 停止抓包
        dut.execute_sudo("pkill -f tcpdump")
        time.sleep(1)
        
        # 检查抓包文件
        stdout, stderr, code = dut.execute_sudo("ls -la /tmp/test_bpdu_capture.pcap")
        if code == 0:
            print(f"抓包文件: {stdout.strip()}")
            
            # 分析抓包内容
            stdout, stderr, code = dut.execute_sudo(
                "tcpdump -r /tmp/test_bpdu_capture.pcap -v 2>/dev/null"
            )
            if code == 0 and stdout.strip():
                print("捕获的BPDU包:")
                print(stdout)
            else:
                print("未捕获到任何BPDU包")
        else:
            print("抓包文件不存在")
        
        # 8. 检查DUT的RSTP统计
        print("\n8. 检查DUT的RSTP统计:")
        stdout, stderr, code = dut.execute_sudo("ovs-vsctl list port")
        if code == 0:
            for line in stdout.split('\n'):
                if 'rstp' in line.lower():
                    print(f"  {line.strip()}")
        
    except Exception as e:
        print(f"测试过程中出错: {e}")
    finally:
        testnode1.close()
        dut.close()
        print("\n连接已关闭")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
调试BPDU注入路径问题
"""

import subprocess
import sys
import time

def run_command(cmd, node_type="local"):
    """执行命令并返回结果"""
    try:
        if node_type == "ssh":
            # SSH命令格式
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        else:
            # 本地命令
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        return "", str(e), 1

def check_testnode1_network():
    """检查TestNode1的网络配置"""
    print("\n=== TestNode1网络配置检查 ===")
    
    # 检查接口状态
    print("\n1. 检查网络接口:")
    stdout, stderr, code = run_command("ssh TestNode1 'ip link show'", "ssh")
    if code == 0:
        print(stdout)
        # 分析eth0是否在网桥中
        if "master br0" in stdout:
            print("⚠️  警告: eth0接口已加入网桥br0，这可能影响BPDU发送")
        else:
            print("✓ eth0接口未加入网桥")
    else:
        print(f"❌ 获取接口信息失败: {stderr}")
    
    # 检查网桥配置
    print("\n2. 检查网桥配置:")
    stdout, stderr, code = run_command("ssh TestNode1 'brctl show'", "ssh")
    if code == 0:
        print(stdout)
    else:
        print(f"❌ 获取网桥信息失败: {stderr}")
    
    # 检查路由表
    print("\n3. 检查路由表:")
    stdout, stderr, code = run_command("ssh TestNode1 'ip route'", "ssh")
    if code == 0:
        print(stdout)
    else:
        print(f"❌ 获取路由信息失败: {stderr}")

def check_dut_network():
    """检查DUT的网络配置"""
    print("\n=== DUT网络配置检查 ===")
    
    # 检查OVS网桥
    print("\n1. 检查OVS网桥:")
    stdout, stderr, code = run_command("ssh DUT 'ovs-vsctl show'", "ssh")
    if code == 0:
        print(stdout)
    else:
        print(f"❌ 获取OVS信息失败: {stderr}")
    
    # 检查网桥接口
    print("\n2. 检查网桥接口:")
    stdout, stderr, code = run_command("ssh DUT 'ip link show | grep br'", "ssh")
    if code == 0:
        print(stdout)
    else:
        print(f"❌ 获取网桥接口失败: {stderr}")

def test_bpdu_capture():
    """测试BPDU抓包功能"""
    print("\n=== 测试BPDU抓包功能 ===")
    
    # 在DUT上启动tcpdump
    print("\n1. 在DUT br3接口启动tcpdump:")
    cmd = "ssh DUT 'timeout 10 tcpdump -i br3 -c 5 -w /tmp/test_capture.pcap ether proto 0x88cc or ether dst 01:80:c2:00:00:00 > /tmp/tcpdump_test.log 2>&1 &'"
    stdout, stderr, code = run_command(cmd, "ssh")
    print(f"tcpdump启动结果: code={code}")
    
    time.sleep(2)
    
    # 从TestNode1发送测试包
    print("\n2. 从TestNode1发送测试BPDU:")
    test_script = '''
from scapy.all import *
import sys

try:
    # 构建简单的BPDU测试包
    eth = Ether(dst="01:80:c2:00:00:00", src="00:11:22:33:44:55")
    llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
    bpdu = STP(
        proto=0x0000,
        version=0x02,
        bpdutype=0x02,
        bpduflags=0x3c,
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
    
    # 尝试不同接口
    interfaces = ["eth0", "eth1", "eth2"]
    for iface in interfaces:
        try:
            print(f"尝试从接口 {iface} 发送BPDU...")
            sendp(packet, iface=iface, verbose=1, count=1)
            print(f"✓ 从 {iface} 发送成功")
            break
        except Exception as e:
            print(f"❌ 从 {iface} 发送失败: {e}")
            continue
    
except Exception as e:
    print(f"BPDU发送失败: {e}")
    sys.exit(1)
'''
    
    # 写入测试脚本
    write_cmd = f"ssh TestNode1 'cat > /tmp/test_bpdu.py << EOF\n{test_script}\nEOF'"
    run_command(write_cmd, "ssh")
    
    # 执行测试脚本
    stdout, stderr, code = run_command("ssh TestNode1 'cd /tmp && python3 test_bpdu.py'", "ssh")
    print(f"BPDU发送结果: code={code}")
    if stdout:
        print(f"STDOUT: {stdout}")
    if stderr:
        print(f"STDERR: {stderr}")
    
    time.sleep(5)
    
    # 检查抓包结果
    print("\n3. 检查抓包结果:")
    stdout, stderr, code = run_command("ssh DUT 'ls -la /tmp/test_capture.pcap'", "ssh")
    if code == 0:
        print(f"✓ 抓包文件存在: {stdout}")
        # 分析抓包文件
        stdout, stderr, code = run_command("ssh DUT 'tcpdump -r /tmp/test_capture.pcap -v'", "ssh")
        if code == 0 and stdout:
            print(f"抓包内容: {stdout}")
        else:
            print("抓包文件为空或无法读取")
    else:
        print("❌ 抓包文件不存在")
    
    # 检查tcpdump日志
    stdout, stderr, code = run_command("ssh DUT 'cat /tmp/tcpdump_test.log'", "ssh")
    if code == 0:
        print(f"tcpdump日志: {stdout}")

def check_network_connectivity():
    """检查网络连通性"""
    print("\n=== 网络连通性检查 ===")
    
    # TestNode1 ping DUT
    print("\n1. TestNode1 ping DUT:")
    stdout, stderr, code = run_command("ssh TestNode1 'ping -c 3 192.168.1.123'", "ssh")
    if code == 0:
        print("✓ TestNode1到DUT连通正常")
    else:
        print(f"❌ TestNode1到DUT连通失败: {stderr}")
    
    # 检查ARP表
    print("\n2. 检查ARP表:")
    stdout, stderr, code = run_command("ssh TestNode1 'arp -a'", "ssh")
    if code == 0:
        print(f"TestNode1 ARP表: {stdout}")
    
    stdout, stderr, code = run_command("ssh DUT 'arp -a'", "ssh")
    if code == 0:
        print(f"DUT ARP表: {stdout}")

def main():
    """主函数"""
    print("=== BPDU注入路径调试工具 ===")
    print("此工具将检查BPDU注入失败的可能原因")
    
    try:
        check_testnode1_network()
        check_dut_network()
        check_network_connectivity()
        test_bpdu_capture()
        
        print("\n=== 调试建议 ===")
        print("1. 如果eth0在网桥中，考虑使用其他接口或临时移除网桥配置")
        print("2. 如果抓包失败，检查DUT的tcpdump权限和接口状态")
        print("3. 如果BPDU发送失败，检查scapy安装和接口权限")
        print("4. 考虑使用原始socket或其他方法发送BPDU")
        
    except KeyboardInterrupt:
        print("\n调试被用户中断")
    except Exception as e:
        print(f"\n调试过程中出错: {e}")

if __name__ == "__main__":
    main()
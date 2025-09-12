#!/usr/bin/env python3
"""
BPDU注入验证测试脚本
用于验证BPDU是否能成功从TestNode1发送到DUT
"""

import sys
import os
import time
import yaml
from pathlib import Path

# 添加src目录到Python路径
sys.path.insert(0, str(Path(__file__).parent / "src"))

from ssh_manager import SSHManager
from fault_injector import FaultInjector

def load_config():
    """加载配置文件"""
    config_path = Path(__file__).parent / "config.yaml"
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def test_bpdu_injection():
    """测试BPDU注入过程"""
    print("=== BPDU注入验证测试 ===")
    
    # 加载配置
    config = load_config()
    
    # 查找TestNode1配置
    testnode1_config = None
    for node in config['vms']['nodes']:
        if node['name'] == 'TestNode1':
            testnode1_config = node
            break
    
    if not testnode1_config:
        print("✗ 未找到TestNode1配置")
        return False
    
    # 连接TestNode1
    testnode1 = SSHManager(
        name=testnode1_config['name'],
        ip=testnode1_config['ip'],
        username=testnode1_config['username'],
        password=testnode1_config['password']
    )
    
    # 连接DUT
    dut_config = config['vms']['dut']
    dut = SSHManager(
        name=dut_config['name'],
        ip=dut_config['ip'],
        username=dut_config['username'],
        password=dut_config['password']
    )
    
    try:
        # 连接测试
        if not testnode1.connect():
            print("✗ TestNode1连接失败")
            return False
        print("✓ TestNode1连接成功")
        
        if not dut.connect():
            print("✗ DUT连接失败")
            return False
        print("✓ DUT连接成功")
        
        # 1. 检查TestNode1的网络接口
        print("\n1. 检查TestNode1网络接口:")
        stdout, stderr, code = testnode1.execute("ip link show")
        if code == 0:
            interfaces = []
            for line in stdout.split('\n'):
                if ': ' in line and 'lo:' not in line:
                    interface = line.split(':')[1].strip().split('@')[0]
                    interfaces.append(interface)
            print(f"可用接口: {interfaces}")
            
            # 检查eth2接口状态
            if 'eth2' in interfaces:
                stdout, stderr, code = testnode1.execute("ip addr show eth2")
                print(f"eth2接口状态:\n{stdout}")
            else:
                print("✗ eth2接口不存在")
                return False
        
        # 2. 在DUT上启动抓包（后台）
        print("\n2. 在DUT上启动抓包:")
        capture_interfaces = ['br3', 'br4']
        capture_pids = []
        
        for iface in capture_interfaces:
            # 检查接口是否存在
            stdout, stderr, code = dut.execute(f"ip link show {iface}")
            if code == 0:
                print(f"✓ {iface}接口存在，启动抓包")
                # 启动tcpdump抓包
                stdout, stderr, code = dut.execute(
                    f"nohup tcpdump -i {iface} -w /tmp/{iface}_bpdu.pcap stp > /tmp/{iface}_tcpdump.log 2>&1 &"
                )
                if code == 0:
                    # 获取进程ID
                    stdout, stderr, code = dut.execute("pgrep -f tcpdump | tail -1")
                    if code == 0 and stdout.strip():
                        capture_pids.append((iface, stdout.strip()))
                        print(f"✓ {iface}抓包已启动 (PID: {stdout.strip()})")
            else:
                print(f"✗ {iface}接口不存在")
        
        # 等待抓包启动
        time.sleep(2)
        
        # 3. 记录DUT的RSTP接收计数
        print("\n3. 记录DUT的RSTP接收计数:")
        stdout, stderr, code = dut.execute("cat /proc/net/dev | grep br")
        if code == 0:
            print(f"注入前网络统计:\n{stdout}")
        
        # 4. 执行BPDU注入
        print("\n4. 执行BPDU注入:")
        fault_injector = FaultInjector(testnode1)
        
        print("开始注入恶意BPDU到eth2接口...")
        success = fault_injector.inject_rogue_bpdu(
            interface="eth2",
            priority=0,
            src_mac="00:11:22:33:44:55",
            count=5,
            interval=1.0
        )
        
        if success:
            print("✓ BPDU注入命令执行成功")
        else:
            print("✗ BPDU注入命令执行失败")
            return False
        
        # 等待注入完成
        print("等待BPDU注入完成...")
        time.sleep(8)
        
        # 5. 检查注入日志
        print("\n5. 检查BPDU注入日志:")
        stdout, stderr, code = testnode1.execute("cat /tmp/rogue_bpdu.log")
        if code == 0:
            print(f"注入日志:\n{stdout}")
        else:
            print(f"✗ 无法读取注入日志: {stderr}")
        
        # 6. 停止抓包并分析
        print("\n6. 停止抓包并分析:")
        total_captured = 0
        
        for iface, pid in capture_pids:
            # 停止tcpdump
            dut.execute(f"kill {pid}")
            time.sleep(1)
            
            # 分析抓包文件
            stdout, stderr, code = dut.execute(f"tcpdump -r /tmp/{iface}_bpdu.pcap -c 100")
            if code == 0:
                packet_count = len([line for line in stdout.split('\n') if line.strip()])
                print(f"{iface}接口捕获到{packet_count}个包")
                if packet_count > 0:
                    print(f"{iface}抓包内容:\n{stdout[:500]}...")
                total_captured += packet_count
            else:
                print(f"✗ 无法分析{iface}抓包文件: {stderr}")
        
        # 7. 记录注入后的网络统计
        print("\n7. 记录注入后的网络统计:")
        stdout, stderr, code = dut.execute("cat /proc/net/dev | grep br")
        if code == 0:
            print(f"注入后网络统计:\n{stdout}")
        
        # 8. 分析结果
        print("\n=== 分析结果 ===")
        if total_captured > 0:
            print(f"✓ 成功捕获到{total_captured}个包，BPDU已送达DUT")
            return True
        else:
            print("✗ 未捕获到任何包，BPDU未送达DUT")
            print("可能的原因:")
            print("1. TestNode1的eth2接口未连接到DUT")
            print("2. BPDU格式不正确")
            print("3. 网络路由问题")
            print("4. DUT的接口配置问题")
            return False
    
    except Exception as e:
        print(f"✗ 测试过程中出现异常: {e}")
        return False
    
    finally:
        # 清理
        try:
            testnode1.close()
            dut.close()
        except:
            pass

if __name__ == "__main__":
    success = test_bpdu_injection()
    if success:
        print("\n=== 测试通过 ===")
        print("BPDU注入验证成功")
    else:
        print("\n=== 测试失败 ===")
        print("BPDU注入验证失败，需要进一步调试")
    
    sys.exit(0 if success else 1)
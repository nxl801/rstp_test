#!/usr/bin/env python3
"""
诊断网络连接问题
"""

import sys
sys.path.append('src')

from ssh_manager import SSHManager
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_dut_connectivity():
    """检查DUT连接性"""
    print("\n=== DUT连接性检查 ===")
    
    # 检查DUT的网络接口
    print("\n1. DUT网络接口状态:")
    import subprocess
    try:
        result = subprocess.run(['python', 'check_dut_interfaces.py'], 
                              capture_output=True, text=True, timeout=30)
        print(result.stdout)
        if result.stderr:
            print(f"错误: {result.stderr}")
    except Exception as e:
        print(f"检查DUT接口失败: {e}")
    
    # 检查物理连接
    print("\n2. 检查物理连接状态:")
    try:
        # 检查br3和br4的链路状态
        result = subprocess.run(['ip', 'link', 'show', 'br3'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"br3状态: {result.stdout.strip()}")
        else:
            print("br3接口不存在")
            
        result = subprocess.run(['ip', 'link', 'show', 'br4'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"br4状态: {result.stdout.strip()}")
        else:
            print("br4接口不存在")
    except Exception as e:
        print(f"检查物理连接失败: {e}")

def check_testnode_connectivity():
    """检查TestNode连接性"""
    print("\n=== TestNode连接性检查 ===")
    
    # TestNode配置
    nodes_config = [
        {'name': 'TestNode1', 'ip': '192.168.13.136'},
        {'name': 'TestNode2', 'ip': '192.168.13.137'}
    ]
    
    for node_config in nodes_config:
        print(f"\n检查 {node_config['name']} ({node_config['ip']}):")
        
        # 先检查网络连通性
        try:
            import subprocess
            result = subprocess.run(['ping', '-n', '1', node_config['ip']], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✓ {node_config['name']} 网络可达")
            else:
                print(f"✗ {node_config['name']} 网络不可达")
                continue
        except Exception as e:
            print(f"✗ ping {node_config['name']} 失败: {e}")
            continue
        
        # 尝试SSH连接
        try:
            node = SSHManager(node_config['name'], node_config['ip'], 'root', 'Schneider123!')
            node.connect()
            print(f"✓ {node_config['name']} SSH连接成功")
            
            # 检查网络接口
            stdout, stderr, code = node.execute("ip link show")
            if code == 0:
                print(f"\n{node_config['name']} 网络接口:")
                lines = stdout.split('\n')
                for line in lines:
                    if ': ' in line and ('eth' in line or 'br' in line):
                        print(f"  {line.strip()}")
            else:
                print(f"获取{node_config['name']}接口失败: {stderr}")
            
            # 检查特定接口
            for iface in ['eth0', 'eth2', 'br0']:
                stdout, stderr, code = node.execute(f"ip link show {iface}")
                if code == 0:
                    status = "UP" if "state UP" in stdout else "DOWN"
                    print(f"  {iface}: 存在 ({status})")
                else:
                    print(f"  {iface}: 不存在")
            
            node.close()
            
        except Exception as e:
            print(f"✗ {node_config['name']} 连接失败: {e}")

def check_bpdu_injection_path():
    """检查BPDU注入路径"""
    print("\n=== BPDU注入路径分析 ===")
    
    print("\n当前测试配置:")
    print("- DUT使用接口: br3, br4 (在SE_ETH2网桥中)")
    print("- TestNode预期接口: eth0, eth2 (在br0网桥中)")
    print("- 当前注入接口: eth2")
    
    print("\n问题分析:")
    print("1. 如果TestNode1没有eth2接口，BPDU注入会失败")
    print("2. 如果eth2存在但没有连接到DUT，BPDU不会到达")
    print("3. 如果SE_ETH2网桥状态为LINK_DOWN，DUT无法接收BPDU")
    
    print("\n建议的解决方案:")
    print("1. 确认TestNode1的实际可用接口")
    print("2. 确认物理连接：TestNode1的接口 <-> DUT的br3/br4")
    print("3. 修改注入接口为实际存在且连接的接口")
    print("4. 确保DUT的SE_ETH2网桥状态正常")

def main():
    """主函数"""
    print("网络连接诊断工具")
    print("=" * 50)
    
    check_dut_connectivity()
    check_testnode_connectivity()
    check_bpdu_injection_path()
    
    print("\n=== 诊断完成 ===")
    print("请根据上述信息修复网络连接问题")

if __name__ == "__main__":
    main()
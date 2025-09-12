#!/usr/bin/env python3

import sys
sys.path.append('.')

from src.ssh_manager import SSHManager
from dataclasses import dataclass

@dataclass
class NodeConfig:
    name: str
    ip: str
    username: str
    password: str

def check_dut_bridge():
    """检查DUT的网桥配置"""# DUT配置
    dut_config = NodeConfig(
        name="DUT",
        ip="192.168.1.123",
        username="root",
        password="1"
    )
    
    dut = SSHManager(dut_config.name, dut_config.ip, dut_config.username, dut_config.password)
    try:
        dut.connect()
        print("=== DUT连接成功 ===")
        
        print("\n=== OVS网桥列表 ===")
        stdout, stderr, code = dut.execute_as_root('ovs-vsctl show')
        print(f"返回码: {code}")
        print(f"输出: {stdout}")
        if stderr:
            print(f"错误: {stderr}")
        
        print("\n=== SE_ETH2端口详情 ===")
        stdout, stderr, code = dut.execute_as_root('ovs-ofctl show SE_ETH2')
        print(f"返回码: {code}")
        print(f"输出: {stdout}")
        if stderr:
            print(f"错误: {stderr}")
        
        print("\n=== 网络接口状态 ===")
        stdout, stderr, code = dut.execute('ip link show')
        print(f"返回码: {code}")
        print(f"输出: {stdout}")
        if stderr:
            print(f"错误: {stderr}")
            
        print("\n=== SE_ETH2 STP状态 ===")
        stdout, stderr, code = dut.execute_as_root('ovs-appctl stp/show SE_ETH2')
        print(f"返回码: {code}")
        print(f"输出: {stdout}")
        if stderr:
            print(f"错误: {stderr}")
        
    except Exception as e:
        print(f"错误: {e}")
    finally:
        dut.close()
        print("\n=== DUT连接已关闭 ===")

if __name__ == "__main__":
    check_dut_bridge()
#!/usr/bin/env python3
import sys
import os
import yaml
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.rstp_analyzer import RSTPAnalyzer
from src.network_topology import NetworkTopology
from src.ssh_manager import SSHManager

# 加载配置
config_path = Path(__file__).parent / "config.yaml"
with open(config_path, 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

# 创建DUT连接
dut_config = config['vms']['dut']
dut_manager = SSHManager(
    name=dut_config['name'],
    ip=dut_config['ip'],
    username=dut_config['username'],
    password=dut_config['password']
)

if dut_manager.connect():
    # 创建分析器和拓扑
    analyzer = RSTPAnalyzer(dut_manager)
    topology = NetworkTopology([dut_manager])  # 传入nodes参数
    
    print("=== DUT RSTP状态 ===")
    bridge_info = analyzer.get_bridge_info('SE_ETH2')
    is_root = analyzer.is_root_bridge()
    
    print(f"Bridge ID: {bridge_info.bridge_id}")
    print(f"Root ID: {bridge_info.root_id}")
    print(f"Root Port: {bridge_info.root_port}")
    print(f"Is Root Bridge: {is_root}")
    print(f"Protocol Version: {bridge_info.protocol_version}")
    
    # 获取端口状态
    print("\n=== 端口状态 ===")
    for port_name, port_info in bridge_info.ports.items():
        print(f"{port_name}: role={port_info.role}, state={port_info.state}")
    
    # 执行OVS命令查看详细信息
    print("\n=== OVS详细信息 ===")
    stdout, stderr, code = dut_manager.execute_as_root("ovs-vsctl show")
    print(f"ovs-vsctl show (返回码: {code}):")
    print(stdout)
    if stderr:
        print(f"错误: {stderr}")
    
    stdout, stderr, code = dut_manager.execute_as_root("ovs-appctl rstp/show SE_ETH2")
    print(f"\novs-appctl rstp/show SE_ETH2 (返回码: {code}):")
    print(stdout)
    if stderr:
        print(f"错误: {stderr}")
    
    dut_manager.close()
else:
    print("无法连接到DUT")
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
启动测试环境中的所有虚拟机
"""

import sys
import time
import yaml
from pathlib import Path
from src.vmware_controller import VMwareController
from src.ssh_manager import SSHManager

def load_config():
    """加载配置文件"""
    config_path = Path("config.yaml")
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def start_vm_and_wait(controller, vm_config, vm_type):
    """启动VM并等待SSH连接就绪"""
    vm_path = vm_config['vm_path']
    vm_name = vm_config['name']
    
    print(f"\n=== 启动{vm_type}: {vm_name} ===")
    
    # 检查VM是否已运行
    if controller.is_running(vm_path):
        print(f"✓ {vm_name} 已在运行")
    else:
        print(f"启动 {vm_name}...")
        if not controller.start_vm(vm_path, headless=True, wait_ready=True):
            print(f"❌ 启动 {vm_name} 失败")
            return False
        print(f"✓ {vm_name} 启动成功")
    
    # 等待SSH连接就绪
    print(f"等待 {vm_name} SSH连接就绪...")
    ssh_manager = SSHManager(
        name=vm_name,
        ip=vm_config['ip'],
        username=vm_config['username'],
        password=vm_config['password']
    )
    
    # 尝试连接SSH，最多等待2分钟
    for attempt in range(24):  # 24次 * 5秒 = 2分钟
        if ssh_manager.connect():
            print(f"✓ {vm_name} SSH连接成功")
            ssh_manager.close()
            return True
        print(f"  尝试 {attempt + 1}/24: SSH连接失败，5秒后重试...")
        time.sleep(5)
    
    print(f"❌ {vm_name} SSH连接超时")
    return False

def check_network_connectivity(config):
    """检查网络连通性"""
    print("\n=== 检查网络连通性 ===")
    
    # 连接到TestNode1
    testnode1_config = None
    for node in config['vms']['nodes']:
        if node['name'] == 'TestNode1':
            testnode1_config = node
            break
    
    if not testnode1_config:
        print("❌ 未找到TestNode1配置")
        return False
    
    dut_config = config['vms']['dut']
    
    # 测试TestNode1到DUT的连通性
    testnode1_ssh = SSHManager(
        name=testnode1_config['name'],
        ip=testnode1_config['ip'],
        username=testnode1_config['username'],
        password=testnode1_config['password']
    )
    
    if not testnode1_ssh.connect():
        print("❌ 无法连接到TestNode1")
        return False
    
    print(f"测试 TestNode1({testnode1_config['ip']}) 到 DUT({dut_config['ip']}) 的连通性...")
    
    # 执行ping测试
    result = testnode1_ssh.execute_command(f"ping -c 3 {dut_config['ip']}")
    if result.success:
        print("✓ TestNode1到DUT连通正常")
        print("Ping结果:")
        print(result.stdout)
    else:
        print("❌ TestNode1到DUT连通失败")
        print(f"错误: {result.stderr}")
        
        # 检查网络配置
        print("\n检查TestNode1网络配置:")
        
        # 检查接口状态
        result = testnode1_ssh.execute_command("ip addr show")
        if result.success:
            print("接口配置:")
            print(result.stdout)
        
        # 检查路由表
        result = testnode1_ssh.execute_command("ip route")
        if result.success:
            print("\n路由表:")
            print(result.stdout)
    
    testnode1_ssh.close()
    return True

def setup_network_for_bpdu_test(config):
    """为BPDU测试设置网络配置"""
    print("\n=== 设置BPDU测试网络配置 ===")
    
    # 连接到TestNode1
    testnode1_config = None
    for node in config['vms']['nodes']:
        if node['name'] == 'TestNode1':
            testnode1_config = node
            break
    
    if not testnode1_config:
        print("❌ 未找到TestNode1配置")
        return False
    
    testnode1_ssh = SSHManager(
        name=testnode1_config['name'],
        ip=testnode1_config['ip'],
        username=testnode1_config['username'],
        password=testnode1_config['password']
    )
    
    if not testnode1_ssh.connect():
        print("❌ 无法连接到TestNode1")
        return False
    
    try:
        # 检查当前网络配置
        print("检查当前网络配置...")
        result = testnode1_ssh.execute_command("ip link show")
        if result.success:
            print("当前接口状态:")
            print(result.stdout)
            
            # 检查eth0是否在网桥中
            if "master br0" in result.stdout:
                print("⚠️  警告: eth0接口在网桥br0中，这可能影响BPDU发送")
                
                # 尝试临时移除eth0从网桥
                print("尝试临时移除eth0从网桥...")
                result = testnode1_ssh.execute_command("sudo brctl delif br0 eth0")
                if result.success:
                    print("✓ 已移除eth0从网桥br0")
                else:
                    print(f"❌ 移除eth0失败: {result.stderr}")
        
        # 确保scapy可用
        print("\n检查scapy安装...")
        result = testnode1_ssh.execute_command("python3 -c 'import scapy.all; print(\"scapy可用\")'")
        if result.success:
            print("✓ scapy已安装")
        else:
            print("❌ scapy未安装，尝试安装...")
            result = testnode1_ssh.execute_command("sudo apt-get update && sudo apt-get install -y python3-scapy")
            if result.success:
                print("✓ scapy安装成功")
            else:
                print(f"❌ scapy安装失败: {result.stderr}")
        
        # 检查网络接口权限
        print("\n检查网络接口权限...")
        result = testnode1_ssh.execute_command("sudo python3 -c 'from scapy.all import *; print(\"scapy权限正常\")'")
        if result.success:
            print("✓ scapy权限正常")
        else:
            print(f"❌ scapy权限问题: {result.stderr}")
        
        return True
        
    finally:
        testnode1_ssh.close()

def main():
    """主函数"""
    print("=== RSTP测试环境启动工具 ===")
    
    try:
        # 加载配置
        config = load_config()
        
        # 初始化VMware控制器
        vmrun_path = config['test_environment']['vmware']['vmrun_path']
        print(f"使用vmrun路径: {vmrun_path}")
        
        try:
            controller = VMwareController(vmrun_path)
        except RuntimeError as e:
            print(f"❌ VMware控制器初始化失败: {e}")
            print("请确保VMware Workstation已安装且vmrun路径正确")
            return False
        
        # 启动DUT
        dut_config = config['vms']['dut']
        if not start_vm_and_wait(controller, dut_config, "DUT"):
            print("❌ DUT启动失败")
            return False
        
        # 启动测试节点
        success_count = 0
        for node_config in config['vms']['nodes']:
            if start_vm_and_wait(controller, node_config, "测试节点"):
                success_count += 1
        
        if success_count == 0:
            print("❌ 所有测试节点启动失败")
            return False
        
        print(f"\n✓ 成功启动 {success_count}/{len(config['vms']['nodes'])} 个测试节点")
        
        # 检查网络连通性
        check_network_connectivity(config)
        
        # 设置BPDU测试网络配置
        setup_network_for_bpdu_test(config)
        
        print("\n=== 测试环境启动完成 ===")
        print("现在可以运行RSTP测试了:")
        print("  python -m pytest tests/test_security.py::TestSecurity::test_root_bridge_hijack_attack -v")
        
        return True
        
    except KeyboardInterrupt:
        print("\n用户中断启动过程")
        return False
    except Exception as e:
        print(f"\n启动过程中出错: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
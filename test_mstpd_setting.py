#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试在testNode2上执行mstpd设置指令
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from ssh_manager import SSHManager
import time

def test_mstpd_setting_on_testnode2():
    """在testNode2上测试mstpd优先级设置"""
    print("="*60)
    print("TestNode2 mstpd设置测试")
    print("="*60)
    
    # TestNode2连接信息
    testnode2_config = {
        'ip': '192.168.13.137',
        'username': 'root',
        'password': '8N10xiaol'
    }
    
    try:
        # 连接到TestNode2
        print(f"\n步骤1: 连接到TestNode2 ({testnode2_config['ip']})")
        ssh_manager = SSHManager(
            name="testNode2",
            ip=testnode2_config['ip'],
            username=testnode2_config['username'],
            password=testnode2_config['password']
        )
        
        if not ssh_manager.connect():
            print(f"❌ 无法连接到TestNode2 ({testnode2_config['ip']})")
            return False
        
        print("✅ 成功连接到TestNode2")
        
        # 检查当前网桥状态
        print("\n步骤2: 检查当前网桥状态")
        stdout, stderr, exit_code = ssh_manager.execute("brctl show")
        print(f"当前网桥状态:\n{stdout}")
        
        # 检查mstpd是否运行
        print("\n步骤3: 检查mstpd服务状态")
        stdout, stderr, exit_code = ssh_manager.execute("ps aux | grep mstpd | grep -v grep")
        if stdout.strip():
            print(f"✅ mstpd服务正在运行:\n{stdout}")
        else:
            print("⚠️ mstpd服务未运行，尝试启动...")
            ssh_manager.execute("sudo systemctl start mstpd")
            time.sleep(2)
        
        # 查找可用的网桥
        print("\n步骤4: 查找可用的网桥")
        stdout, stderr, exit_code = ssh_manager.execute("mstpctl showbridge")
        print(f"当前网桥信息:\n{stdout}")
        
        if not stdout.strip():
            print("⚠️ 未找到mstpd管理的网桥，尝试创建测试网桥...")
            # 创建测试网桥
            ssh_manager.execute("sudo brctl addbr br0")
            ssh_manager.execute("sudo brctl addif br0 eth2")
            ssh_manager.execute("sudo ip link set br0 up")
            ssh_manager.execute("sudo mstpctl addbridge br0")
            time.sleep(2)
            
            # 再次检查
            stdout, stderr, exit_code = ssh_manager.execute("mstpctl showbridge")
            print(f"创建网桥后的状态:\n{stdout}")
        
        # 获取网桥名称
        bridge_name = "br0"  # 默认使用br0
        
        # 步骤5: 查看当前优先级
        print(f"\n步骤5: 查看网桥 {bridge_name} 当前优先级")
        stdout, stderr, exit_code = ssh_manager.execute(f"mstpctl showbridge {bridge_name}")
        print(f"当前网桥详细信息:\n{stdout}")
        
        # 步骤6: 设置新的优先级
        new_priority = 8192
        print(f"\n步骤6: 设置网桥 {bridge_name} 优先级为 {new_priority}")
        
        # 执行设置命令
        cmd = f"mstpctl settreeprio {bridge_name} 0 {new_priority}"
        print(f"执行命令: sudo {cmd}")
        
        stdout, stderr, exit_code = ssh_manager.execute(f"sudo {cmd}")
        
        print(f"命令执行结果:")
        print(f"  退出码: {exit_code}")
        print(f"  标准输出: '{stdout}'")
        print(f"  标准错误: '{stderr}'")
        
        # 步骤7: 验证设置是否成功
        print(f"\n步骤7: 验证优先级设置是否成功")
        time.sleep(1)  # 等待设置生效
        
        stdout, stderr, exit_code = ssh_manager.execute(f"mstpctl showbridge {bridge_name}")
        print(f"设置后的网桥信息:\n{stdout}")
        
        # 检查优先级是否已更改
        if str(new_priority) in stdout:
            print(f"✅ 优先级设置成功！在输出中找到了 {new_priority}")
        else:
            print(f"⚠️ 优先级设置可能未生效，请检查输出")
        
        # 步骤8: 使用其他命令验证
        print(f"\n步骤8: 使用其他命令进行验证")
        
        # 使用mstpctl showtree命令
        stdout, stderr, exit_code = ssh_manager.execute(f"mstpctl showtree {bridge_name}")
        print(f"生成树信息:\n{stdout}")
        
        # 使用mstpctl showportdetail命令
        stdout, stderr, exit_code = ssh_manager.execute(f"mstpctl showportdetail {bridge_name}")
        print(f"端口详细信息:\n{stdout}")
        
        print("\n" + "="*60)
        print("测试完成")
        print("="*60)
        
        return True
        
    except Exception as e:
        print(f"❌ 测试过程中发生错误: {e}")
        return False
    
    finally:
        if 'ssh_manager' in locals() and ssh_manager.client:
            ssh_manager.client.close()
            print("\n🔌 已断开SSH连接")

def analyze_mstpd_result():
    """分析mstpd设置结果的方法"""
    print("\n" + "="*60)
    print("如何确认mstpd优先级设置成功")
    print("="*60)
    
    print("\n1. 检查命令返回值:")
    print("   - 退出码为0表示命令执行成功")
    print("   - 通常mstpctl settreeprio命令成功时不输出任何内容")
    
    print("\n2. 验证方法:")
    print("   - mstpctl showbridge <bridge_name>: 显示网桥基本信息")
    print("   - mstpctl showtree <bridge_name>: 显示生成树详细信息")
    print("   - mstpctl showportdetail <bridge_name>: 显示端口详细信息")
    
    print("\n3. 关键字段:")
    print("   - Bridge Priority: 网桥优先级")
    print("   - Root Priority: 根桥优先级")
    print("   - Designated Priority: 指定桥优先级")
    
    print("\n4. 常见问题:")
    print("   - 如果mstpd未运行，需要先启动服务")
    print("   - 如果网桥不存在，需要先创建并添加到mstpd")
    print("   - 优先级必须是4096的倍数")

if __name__ == "__main__":
    # 执行测试
    success = test_mstpd_setting_on_testnode2()
    
    # 显示分析方法
    analyze_mstpd_result()
    
    if success:
        print("\n✅ 测试执行完成")
    else:
        print("\n❌ 测试执行失败")
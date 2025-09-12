#!/usr/bin/env python3
"""
检查DUT上的网络接口
"""

import sys
sys.path.append('src')

from ssh_manager import SSHManager, SSHConfig

def main():
    # 创建DUT连接
    dut = SSHManager("DUT", "192.168.1.123", "root", "1")
    
    try:
        # 连接DUT
        if not dut.connect():
            print("无法连接到DUT")
            return
        
        print("=== DUT网络接口检查 ===")
        
        # 1. 检查所有网络接口
        stdout, stderr, exit_code = dut.execute("ip link show")
        print(f"\n1. 网络接口列表:")
        print(stdout)
        
        # 2. 检查eth0和eth2接口状态
        for iface in ['eth0', 'eth2']:
            stdout, stderr, exit_code = dut.execute(f"ip link show {iface}")
            print(f"\n2. {iface}接口状态:")
            if exit_code == 0:
                print(stdout)
            else:
                print(f"接口{iface}不存在或无法访问: {stderr}")
        
        # 3. 检查SE_ETH2网桥当前端口
        stdout, stderr, exit_code = dut.execute("ovs-vsctl list-ports SE_ETH2")
        print(f"\n3. SE_ETH2网桥当前端口:")
        if exit_code == 0:
            print(stdout if stdout.strip() else "无端口")
        else:
            print(f"获取端口列表失败: {stderr}")
        
        # 4. 尝试手动添加eth0到SE_ETH2
        print(f"\n4. 尝试添加eth0到SE_ETH2网桥:")
        stdout, stderr, exit_code = dut.execute_as_root("ovs-vsctl add-port SE_ETH2 eth0")
        if exit_code == 0:
            print("eth0添加成功")
        else:
            print(f"eth0添加失败: {stderr}")
        
        # 5. 尝试手动添加eth2到SE_ETH2
        print(f"\n5. 尝试添加eth2到SE_ETH2网桥:")
        stdout, stderr, exit_code = dut.execute_as_root("ovs-vsctl add-port SE_ETH2 eth2")
        if exit_code == 0:
            print("eth2添加成功")
        else:
            print(f"eth2添加失败: {stderr}")
        
        # 6. 再次检查SE_ETH2网桥端口
        stdout, stderr, exit_code = dut.execute("ovs-vsctl list-ports SE_ETH2")
        print(f"\n6. 添加后SE_ETH2网桥端口:")
        if exit_code == 0:
            print(stdout if stdout.strip() else "无端口")
        else:
            print(f"获取端口列表失败: {stderr}")
        
        # 7. 使用ovs-ofctl show检查端口信息
        stdout, stderr, exit_code = dut.execute("ovs-ofctl show SE_ETH2")
        print(f"\n7. ovs-ofctl show SE_ETH2:")
        if exit_code == 0:
            print(stdout)
        else:
            print(f"ovs-ofctl show失败: {stderr}")
            
    except Exception as e:
        print(f"检查过程中发生错误: {e}")
    finally:
        if dut.client:
            dut.client.close()

if __name__ == "__main__":
    main()
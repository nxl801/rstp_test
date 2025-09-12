#!/usr/bin/env python3
"""
检查TestNode1上的网络接口
"""

import sys
sys.path.append('src')

from ssh_manager import SSHManager

def main():
    # 创建TestNode1连接
    node1 = SSHManager('TestNode1', '192.168.13.136', 'root', 'Schneider123!')
    
    try:
        node1.connect()
        print("TestNode1连接成功")
        
        # 1. 检查所有网络接口
        print("\n1. TestNode1所有网络接口:")
        stdout, stderr, code = node1.execute("ip link show")
        if code == 0:
            print(stdout)
        else:
            print(f"获取接口失败: {stderr}")
        
        # 2. 检查eth0接口
        print("\n2. eth0接口状态:")
        stdout, stderr, code = node1.execute("ip link show eth0")
        if code == 0:
            print(stdout)
        else:
            print(f"接口eth0不存在或无法访问: {stderr}")
        
        # 3. 检查eth2接口
        print("\n3. eth2接口状态:")
        stdout, stderr, code = node1.execute("ip link show eth2")
        if code == 0:
            print(stdout)
        else:
            print(f"接口eth2不存在或无法访问: {stderr}")
        
        # 4. 检查br0网桥
        print("\n4. br0网桥状态:")
        stdout, stderr, code = node1.execute("ip link show br0")
        if code == 0:
            print(stdout)
        else:
            print(f"网桥br0不存在: {stderr}")
        
        # 5. 检查网桥端口
        print("\n5. br0网桥端口:")
        stdout, stderr, code = node1.execute("brctl show br0")
        if code == 0:
            print(stdout)
        else:
            print(f"获取网桥端口失败: {stderr}")
            
    except Exception as e:
        print(f"连接或操作失败: {e}")
    finally:
        node1.disconnect()
        print("\nTestNode1连接已关闭")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
检查BPDU注入日志
"""

import yaml
from src.ssh_manager import SSHManager

def main():
    # 加载配置
    with open('config.yaml', 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    # 连接TestNode1
    testnode1_config = None
    for node_config in config['vms']['nodes']:
        if node_config['name'] == 'TestNode1':
            testnode1_config = node_config
            break
    
    if not testnode1_config:
        print("未找到TestNode1配置")
        return
    
    # 创建SSH连接
    testnode1 = SSHManager(
        name='TestNode1',
        ip=testnode1_config['ip'],
        username=testnode1_config['username'],
        password=testnode1_config['password']
    )
    
    print("=== 检查BPDU注入相关文件 ===")
    
    # 检查脚本文件
    print("\n1. 检查BPDU注入脚本:")
    stdout, stderr, code = testnode1.execute("ls -la /tmp/rogue_bpdu.py")
    if code == 0:
        print("脚本文件存在:")
        print(stdout)
    else:
        print("脚本文件不存在")
    
    # 检查日志文件
    print("\n2. 检查BPDU注入日志:")
    stdout, stderr, code = testnode1.execute("ls -la /tmp/rogue_bpdu.log")
    if code == 0:
        print("日志文件存在:")
        print(stdout)
        
        # 读取日志内容
        print("\n3. 日志内容:")
        stdout, stderr, code = testnode1.execute("cat /tmp/rogue_bpdu.log")
        if code == 0:
            print(stdout)
        else:
            print("无法读取日志文件")
    else:
        print("日志文件不存在")
    
    # 检查是否有Python进程在运行
    print("\n4. 检查Python进程:")
    stdout, stderr, code = testnode1.execute("ps aux | grep python | grep -v grep")
    if code == 0 and stdout.strip():
        print("Python进程:")
        print(stdout)
    else:
        print("没有Python进程在运行")
    
    # 检查网络接口状态
    print("\n5. 检查网络接口状态:")
    stdout, stderr, code = testnode1.execute("ip link show")
    if code == 0:
        print("网络接口:")
        print(stdout)
    
    # 手动测试BPDU发送
    print("\n6. 手动测试BPDU发送:")
    test_script = '''#!/usr/bin/env python3
from scapy.all import *
import time

print("测试BPDU发送...")
try:
    # 构建BPDU包
    eth = Ether(dst="01:80:c2:00:00:00", src="00:11:22:33:44:55")
    llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
    bpdu = STP(
        bpdutype=0x02,
        bpduflags=0x3C,
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
    sendp(packet, iface="eth2", verbose=1)
    print("测试BPDU发送成功")
except Exception as e:
    print("测试BPDU发送失败:", str(e))
    import traceback
    traceback.print_exc()
'''
    
    # 写入测试脚本
    testnode1.execute(f"echo '{test_script}' > /tmp/test_bpdu.py")
    testnode1.execute("chmod +x /tmp/test_bpdu.py")
    
    # 执行测试脚本
    stdout, stderr, code = testnode1.execute_sudo("python3 /tmp/test_bpdu.py")
    print(f"测试结果 (code={code}):")
    if stdout:
        print("STDOUT:", stdout)
    if stderr:
        print("STDERR:", stderr)
    
    # 清理
    testnode1.execute("rm -f /tmp/test_bpdu.py")
    
    testnode1.close()
    print("\n检查完成")

if __name__ == "__main__":
    main()
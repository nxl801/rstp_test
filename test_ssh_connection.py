#!/usr/bin/env python3
"""
独立SSH连接测试脚本
用于诊断DUT连接问题
"""

import paramiko
import time
import sys

def test_ssh_connection():
    """测试SSH连接"""
    # DUT连接信息
    hostname = "192.168.1.123"
    username = "user"
    password = "1"
    port = 22
    
    print(f"开始测试SSH连接到 {hostname}...")
    print(f"用户名: {username}")
    print(f"端口: {port}")
    print("-" * 50)
    
    try:
        # 创建SSH客户端
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print("正在连接...")
        start_time = time.time()
        
        # 尝试连接
        client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            timeout=30,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=30
        )
        
        connect_time = time.time() - start_time
        print(f"✅ SSH连接成功！耗时: {connect_time:.2f}秒")
        
        # 测试执行命令
        print("\n测试执行命令...")
        stdin, stdout, stderr = client.exec_command("whoami")
        result = stdout.read().decode().strip()
        print(f"命令执行结果: {result}")
        
        # 测试系统信息
        stdin, stdout, stderr = client.exec_command("uname -a")
        system_info = stdout.read().decode().strip()
        print(f"系统信息: {system_info}")
        
        # 关闭连接
        client.close()
        print("\n✅ 连接测试完成，一切正常！")
        return True
        
    except paramiko.AuthenticationException as e:
        print(f"❌ 认证失败: {e}")
        print("请检查用户名和密码是否正确")
        return False
        
    except paramiko.SSHException as e:
        print(f"❌ SSH连接错误: {e}")
        print("可能的原因:")
        print("1. SSH服务未启动")
        print("2. 防火墙阻止连接")
        print("3. SSH配置问题")
        return False
        
    except Exception as e:
        print(f"❌ 连接失败: {e}")
        print(f"错误类型: {type(e).__name__}")
        
        # 详细诊断
        print("\n🔍 详细诊断信息:")
        if "10060" in str(e):
            print("- WinError 10060: 连接超时")
            print("- 可能原因: 目标主机无响应或网络不通")
            print("- 建议检查: ping命令测试网络连通性")
        elif "10061" in str(e):
            print("- WinError 10061: 连接被拒绝")
            print("- 可能原因: SSH服务未启动或端口被阻止")
            print("- 建议检查: SSH服务状态和防火墙设置")
        
        return False
    
    finally:
        try:
            client.close()
        except:
            pass

def test_network_connectivity():
    """测试网络连通性"""
    import subprocess
    import platform
    
    hostname = "192.168.1.123"
    print(f"\n🌐 测试网络连通性到 {hostname}...")
    
    # 根据操作系统选择ping命令
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "4", hostname]
    else:
        cmd = ["ping", "-c", "4", hostname]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✅ 网络连通性正常")
            print("Ping统计信息:")
            for line in result.stdout.split('\n')[-4:]:
                if line.strip():
                    print(f"  {line}")
            return True
        else:
            print("❌ 网络不通")
            print(f"Ping输出: {result.stdout}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ Ping超时")
        return False
    except Exception as e:
        print(f"❌ Ping测试失败: {e}")
        return False

def main():
    """主函数"""
    print("=" * 60)
    print("SSH连接诊断工具")
    print("=" * 60)
    
    # 测试网络连通性
    network_ok = test_network_connectivity()
    
    print("\n" + "=" * 60)
    
    # 测试SSH连接
    ssh_ok = test_ssh_connection()
    
    print("\n" + "=" * 60)
    print("诊断总结:")
    print(f"网络连通性: {'✅ 正常' if network_ok else '❌ 异常'}")
    print(f"SSH连接: {'✅ 正常' if ssh_ok else '❌ 异常'}")
    
    if not network_ok:
        print("\n建议:")
        print("1. 检查DUT设备是否开机")
        print("2. 检查网络配置和路由")
        print("3. 检查防火墙设置")
    elif not ssh_ok:
        print("\n建议:")
        print("1. 检查DUT上SSH服务状态: systemctl status ssh")
        print("2. 检查SSH配置: /etc/ssh/sshd_config")
        print("3. 检查防火墙SSH端口: ufw status")
        print("4. 重启SSH服务: systemctl restart ssh")
    
    return 0 if (network_ok and ssh_ok) else 1

if __name__ == "__main__":
    sys.exit(main())
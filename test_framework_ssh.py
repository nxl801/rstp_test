#!/usr/bin/env python3
"""
测试框架SSH连接
模拟框架的配置加载和SSH管理器初始化过程
"""

import os
import sys
import yaml
from pathlib import Path

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.ssh_manager import SSHManager

def load_config():
    """加载配置文件"""
    config_path = Path(__file__).parent / "config.yaml"
    print(f"配置文件路径: {config_path}")
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    print("配置文件加载成功")
    return config

def test_dut_connection():
    """测试DUT连接"""
    print("=" * 60)
    print("框架SSH连接测试")
    print("=" * 60)
    
    try:
        # 加载配置
        print("\n1. 加载配置文件...")
        config = load_config()
        
        # 获取DUT配置
        dut_config = config['vms']['dut']
        print(f"DUT配置: {dut_config}")
        
        # 创建SSH管理器
        print("\n2. 创建SSH管理器...")
        manager = SSHManager(
            name=dut_config['name'],
            ip=dut_config['ip'],
            username=dut_config['username'],
            password=dut_config['password']
        )
        
        print(f"SSH管理器创建成功:")
        print(f"  名称: {manager.config.name}")
        print(f"  IP: {manager.config.ip}")
        print(f"  用户名: {manager.config.username}")
        print(f"  端口: {manager.config.port}")
        print(f"  超时: {manager.config.timeout}")
        
        # 尝试连接
        print("\n3. 尝试SSH连接...")
        if manager.connect():
            print("✅ SSH连接成功！")
            
            # 测试命令执行
            print("\n4. 测试命令执行...")
            stdout, stderr, code = manager.execute("whoami")
            print(f"命令: whoami")
            print(f"返回码: {code}")
            print(f"输出: {stdout.strip()}")
            if stderr:
                print(f"错误: {stderr.strip()}")
            
            # 测试sudo命令
            print("\n5. 测试sudo命令...")
            stdout, stderr, code = manager.execute_sudo("whoami")
            print(f"命令: sudo whoami")
            print(f"返回码: {code}")
            print(f"输出: {stdout.strip()}")
            if stderr:
                print(f"错误: {stderr.strip()}")
            
            # 关闭连接
            manager.close()
            print("\n✅ 框架SSH连接测试完成，一切正常！")
            return True
            
        else:
            print("❌ SSH连接失败")
            return False
            
    except Exception as e:
        print(f"❌ 测试过程中发生错误: {e}")
        print(f"错误类型: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主函数"""
    success = test_dut_connection()
    
    print("\n" + "=" * 60)
    print("测试总结:")
    if success:
        print("✅ 框架SSH连接正常，问题可能在pytest或测试用例中")
        print("\n建议检查:")
        print("1. pytest fixture的初始化顺序")
        print("2. 测试用例的依赖关系")
        print("3. 并发连接问题")
    else:
        print("❌ 框架SSH连接异常")
        print("\n需要进一步调试框架代码")
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
"""
测试CPU使用率获取修复
"""

import sys
import os
import logging
from unittest.mock import Mock

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 设置日志
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 导入测试类
from tests.test_security import TestSecurity

def create_mock_node():
    """创建模拟节点"""
    mock_node = Mock()
    
    # 模拟不同命令的返回结果
    def mock_execute(command):
        logger.debug(f"模拟执行命令: {command}")
        
        # 模拟top命令失败（常见情况）
        if "top -bn1" in command and "grep 'Cpu(s)'" in command:
            return "", "top: command not found", 127
        
        # 模拟top命令完整输出
        elif "top -bn1" in command and "head -10" in command:
            output = """top - 14:30:15 up 1 day,  2:34,  1 user,  load average: 0.15, 0.10, 0.05
Tasks: 123 total,   1 running, 122 sleeping,   0 stopped,   0 zombie
%Cpu(s): 15.2 us,  2.1 sy,  0.0 ni, 82.1 id,  0.4 wa,  0.0 hi,  0.2 si,  0.0 st
KiB Mem :  8192000 total,  4096000 free,  2048000 used,  2048000 buff/cache
KiB Swap:  2097152 total,  2097152 free,        0 used.  5120000 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
 1234 root      20   0  123456   7890   1234 S   5.2  0.1   0:12.34 test_process
 5678 user      20   0   98765   4321    987 S   2.1  0.1   0:05.67 another_proc
 9012 daemon    20   0   54321   2109    543 S   1.0  0.0   0:02.10 system_daemon"""
            return output, "", 0
        
        # 模拟/proc/stat读取
        elif "cat /proc/stat" in command:
            # 第一次和第二次读取返回不同的值来模拟CPU使用
            if not hasattr(mock_execute, 'proc_stat_count'):
                mock_execute.proc_stat_count = 0
            
            mock_execute.proc_stat_count += 1
            
            if mock_execute.proc_stat_count == 1:
                # 第一次读取
                return "cpu  1000000 50000 200000 8000000 10000 0 5000 0 0 0", "", 0
            else:
                # 第二次读取（1秒后，模拟CPU使用）
                return "cpu  1001500 50100 200200 8000800 10010 0 5010 0 0 0", "", 0
        
        # 模拟sleep命令
        elif "sleep 1" in command:
            return "", "", 0
        
        # 模拟vmstat命令
        elif "vmstat 1 2" in command:
            output = """procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 1  0      0 4096000 256000 2048000    0    0     5    10  100  200 12  3 84  1  0
 0  0      0 4095000 256100 2048100    0    0     2     5   95  180 15  2 82  1  0"""
            return output, "", 0
        
        # 默认返回失败
        else:
            return "", f"Command not found: {command}", 127
    
    mock_node.execute = mock_execute
    return mock_node

def test_cpu_usage_methods():
    """测试各种CPU使用率获取方法"""
    logger.info("开始测试CPU使用率获取方法")
    
    # 创建测试实例
    test_security = TestSecurity()
    mock_node = create_mock_node()
    
    # 测试主方法
    logger.info("\n=== 测试主CPU获取方法 ===")
    cpu_usage = test_security._get_cpu_usage(mock_node)
    logger.info(f"最终CPU使用率: {cpu_usage}%")
    
    # 测试各个子方法
    logger.info("\n=== 测试各个子方法 ===")
    
    # 方法1: top命令标准格式
    logger.info("\n--- 测试方法1: top命令标准格式 ---")
    try:
        cpu1 = test_security._get_cpu_usage_top_method1(mock_node)
        logger.info(f"方法1结果: {cpu1}%")
    except Exception as e:
        logger.info(f"方法1失败: {e}")
    
    # 方法2: top命令完整输出解析
    logger.info("\n--- 测试方法2: top命令完整输出解析 ---")
    try:
        cpu2 = test_security._get_cpu_usage_top_method2(mock_node)
        logger.info(f"方法2结果: {cpu2}%")
    except Exception as e:
        logger.info(f"方法2失败: {e}")
    
    # 方法3: /proc/stat计算
    logger.info("\n--- 测试方法3: /proc/stat计算 ---")
    try:
        # 重置计数器
        if hasattr(mock_node.execute, 'proc_stat_count'):
            delattr(mock_node.execute, 'proc_stat_count')
        cpu3 = test_security._get_cpu_usage_proc_stat(mock_node)
        logger.info(f"方法3结果: {cpu3}%")
    except Exception as e:
        logger.info(f"方法3失败: {e}")
    
    # 方法4: vmstat命令
    logger.info("\n--- 测试方法4: vmstat命令 ---")
    try:
        cpu4 = test_security._get_cpu_usage_vmstat(mock_node)
        logger.info(f"方法4结果: {cpu4}%")
    except Exception as e:
        logger.info(f"方法4失败: {e}")
    
    # 验证结果
    logger.info("\n=== 测试结果验证 ===")
    if cpu_usage > 0.0:
        logger.info(f"✓ CPU使用率获取成功: {cpu_usage}%")
        logger.info("✓ 修复方案有效，不再返回0.0%")
    else:
        logger.warning("✗ CPU使用率仍为0.0%，需要进一步调试")
    
    return cpu_usage

def test_real_environment():
    """测试真实环境（如果可能）"""
    logger.info("\n=== 测试真实环境 ===")
    
    # 尝试在本地执行一些命令来验证
    import subprocess
    
    commands_to_test = [
        "wmic cpu get loadpercentage /value",  # Windows命令
        "typeperf \"\\Processor(_Total)\\% Processor Time\" -sc 1",  # Windows性能计数器
    ]
    
    for cmd in commands_to_test:
        try:
            logger.info(f"测试本地命令: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            logger.info(f"返回码: {result.returncode}")
            logger.info(f"输出: {result.stdout[:200]}...")
            if result.stderr:
                logger.info(f"错误: {result.stderr[:200]}...")
        except Exception as e:
            logger.info(f"命令执行失败: {e}")

if __name__ == "__main__":
    logger.info("CPU使用率获取修复测试")
    logger.info("=" * 50)
    
    # 测试模拟环境
    cpu_result = test_cpu_usage_methods()
    
    # 测试真实环境
    test_real_environment()
    
    logger.info("\n=== 总结 ===")
    logger.info(f"模拟环境CPU使用率: {cpu_result}%")
    logger.info("测试完成！")
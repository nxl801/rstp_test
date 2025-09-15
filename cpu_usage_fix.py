#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPU使用率获取修复方案
解决test_security.py中CPU使用率一直返回0.0%的问题
"""

import re
import logging
from typing import Tuple, Any

logger = logging.getLogger(__name__)

def get_cpu_usage_improved(node: Any) -> float:
    """
    改进的CPU使用率获取方法
    支持多种Linux发行版和不同的top命令格式
    """
    methods = [
        _get_cpu_usage_top_method1,
        _get_cpu_usage_top_method2,
        _get_cpu_usage_proc_stat,
        _get_cpu_usage_vmstat,
        _get_cpu_usage_iostat
    ]
    
    for method in methods:
        try:
            cpu_usage = method(node)
            if cpu_usage > 0.0:  # 如果获取到有效值，直接返回
                logger.info(f"CPU使用率获取成功: {cpu_usage}% (方法: {method.__name__})")
                return cpu_usage
        except Exception as e:
            logger.debug(f"CPU获取方法 {method.__name__} 失败: {e}")
            continue
    
    logger.warning("所有CPU使用率获取方法都失败，返回0.0")
    return 0.0

def _get_cpu_usage_top_method1(node: Any) -> float:
    """方法1: 标准top命令格式 (Ubuntu/Debian)"""
    stdout, stderr, code = node.execute(
        "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1"
    )
    if code == 0 and stdout.strip():
        return float(stdout.strip())
    raise Exception(f"Method1 failed: code={code}, stdout='{stdout}', stderr='{stderr}'")

def _get_cpu_usage_top_method2(node: Any) -> float:
    """方法2: 不同格式的top命令 (CentOS/RHEL)"""
    stdout, stderr, code = node.execute(
        "top -bn1 | head -10"
    )
    if code == 0:
        # 查找CPU使用率行
        lines = stdout.split('\n')
        for line in lines:
            # 匹配各种可能的CPU行格式
            patterns = [
                r'%Cpu\(s\):\s*([0-9.]+)\s*us',  # CentOS格式
                r'Cpu\(s\):\s*([0-9.]+)%\s*us',   # Ubuntu格式
                r'CPU:\s*([0-9.]+)%\s*usr',       # 其他格式
            ]
            
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    return float(match.group(1))
    
    raise Exception(f"Method2 failed: code={code}")

def _get_cpu_usage_proc_stat(node: Any) -> float:
    """方法3: 使用/proc/stat计算CPU使用率"""
    # 第一次读取
    stdout1, stderr1, code1 = node.execute("cat /proc/stat | head -1")
    if code1 != 0:
        raise Exception(f"Failed to read /proc/stat: {stderr1}")
    
    # 等待1秒
    node.execute("sleep 1")
    
    # 第二次读取
    stdout2, stderr2, code2 = node.execute("cat /proc/stat | head -1")
    if code2 != 0:
        raise Exception(f"Failed to read /proc/stat second time: {stderr2}")
    
    # 解析CPU时间
    def parse_cpu_times(line):
        parts = line.strip().split()
        if len(parts) < 8:
            raise Exception(f"Invalid /proc/stat format: {line}")
        # user, nice, system, idle, iowait, irq, softirq, steal
        return [int(x) for x in parts[1:8]]
    
    times1 = parse_cpu_times(stdout1)
    times2 = parse_cpu_times(stdout2)
    
    # 计算差值
    diffs = [times2[i] - times1[i] for i in range(len(times1))]
    total_diff = sum(diffs)
    
    if total_diff == 0:
        return 0.0
    
    # idle时间是第4个值（索引3）
    idle_diff = diffs[3]
    cpu_usage = (1.0 - idle_diff / total_diff) * 100.0
    
    return max(0.0, min(100.0, cpu_usage))

def _get_cpu_usage_vmstat(node: Any) -> float:
    """方法4: 使用vmstat命令"""
    stdout, stderr, code = node.execute("vmstat 1 2 | tail -1")
    if code == 0 and stdout.strip():
        parts = stdout.strip().split()
        if len(parts) >= 15:
            # vmstat输出格式: ... us sy id wa st
            # idle是倒数第3个字段
            idle = float(parts[-3])
            cpu_usage = 100.0 - idle
            return max(0.0, min(100.0, cpu_usage))
    
    raise Exception(f"vmstat failed: code={code}, stdout='{stdout}'")

def _get_cpu_usage_iostat(node: Any) -> float:
    """方法5: 使用iostat命令（如果可用）"""
    stdout, stderr, code = node.execute("iostat -c 1 1 | tail -2 | head -1")
    if code == 0 and stdout.strip():
        parts = stdout.strip().split()
        if len(parts) >= 6:
            # iostat输出格式: %user %nice %system %iowait %steal %idle
            idle = float(parts[-1])
            cpu_usage = 100.0 - idle
            return max(0.0, min(100.0, cpu_usage))
    
    raise Exception(f"iostat failed: code={code}, stdout='{stdout}'")

def test_cpu_methods():
    """测试各种CPU获取方法"""
    print("=== CPU使用率获取方法测试 ===")
    
    # 模拟SSH节点
    class MockNode:
        def execute(self, command):
            print(f"执行命令: {command}")
            # 这里应该返回实际的SSH执行结果
            return "", "", 1
    
    node = MockNode()
    result = get_cpu_usage_improved(node)
    print(f"CPU使用率: {result}%")

if __name__ == "__main__":
    test_cpu_methods()
#!/usr/bin/env python3
"""
Windows兼容的CPU使用率获取方法
适用于通过SSH连接到Linux系统的场景
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

class CPUUsageHelper:
    """CPU使用率获取助手类"""
    
    def __init__(self):
        self.methods = [
            self._get_cpu_usage_top_method1,
            self._get_cpu_usage_top_method2, 
            self._get_cpu_usage_proc_stat,
            self._get_cpu_usage_vmstat,
            self._get_cpu_usage_sar,
            self._get_cpu_usage_iostat
        ]
    
    def get_cpu_usage(self, node: Any) -> float:
        """获取CPU使用率 - 多方法容错版本"""
        for method in self.methods:
            try:
                cpu_usage = method(node)
                if cpu_usage >= 0.0:  # 如果获取到有效值，直接返回
                    logger.debug(f"CPU使用率获取成功: {cpu_usage}% (方法: {method.__name__})")
                    return cpu_usage
            except Exception as e:
                logger.debug(f"CPU获取方法 {method.__name__} 失败: {e}")
                continue
        
        logger.warning("所有CPU使用率获取方法都失败，返回0.0")
        return 0.0
    
    def _get_cpu_usage_top_method1(self, node: Any) -> float:
        """方法1: 标准top命令格式 (Ubuntu/Debian)"""
        stdout, stderr, code = node.execute(
            "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1"
        )
        if code == 0 and stdout.strip():
            return float(stdout.strip())
        raise Exception(f"Method1 failed: code={code}, stdout='{stdout}', stderr='{stderr}'")
    
    def _get_cpu_usage_top_method2(self, node: Any) -> float:
        """方法2: 解析top命令完整输出"""
        stdout, stderr, code = node.execute("top -bn1 | head -10")
        if code == 0:
            lines = stdout.split('\n')
            for line in lines:
                # 匹配各种可能的CPU行格式
                patterns = [
                    r'%Cpu\(s\):\s*([0-9.]+)\s*us',  # CentOS格式
                    r'Cpu\(s\):\s*([0-9.]+)%\s*us',   # Ubuntu格式
                    r'CPU:\s*([0-9.]+)%\s*usr',       # 其他格式
                    r'Cpu\(s\):\s*([0-9.]+)%us',      # 紧凑格式
                    r'%Cpu\(s\):\s*([0-9.]+)\s*user', # 另一种格式
                    r'Cpu\(s\):\s*([0-9.]+)\s*us',    # 无百分号格式
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        return float(match.group(1))
        
        raise Exception(f"Method2 failed: code={code}")
    
    def _get_cpu_usage_proc_stat(self, node: Any) -> float:
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
    
    def _get_cpu_usage_vmstat(self, node: Any) -> float:
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
    
    def _get_cpu_usage_sar(self, node: Any) -> float:
        """方法5: 使用sar命令"""
        stdout, stderr, code = node.execute("sar -u 1 1 | tail -1")
        if code == 0 and stdout.strip():
            parts = stdout.strip().split()
            if len(parts) >= 6:
                # sar输出格式: time %user %nice %system %iowait %steal %idle
                try:
                    idle = float(parts[-1])  # 最后一列是idle
                    cpu_usage = 100.0 - idle
                    return max(0.0, min(100.0, cpu_usage))
                except ValueError:
                    pass
        
        raise Exception(f"sar failed: code={code}, stdout='{stdout}'")
    
    def _get_cpu_usage_iostat(self, node: Any) -> float:
        """方法6: 使用iostat命令"""
        stdout, stderr, code = node.execute("iostat -c 1 1 | tail -2 | head -1")
        if code == 0 and stdout.strip():
            parts = stdout.strip().split()
            if len(parts) >= 6:
                # iostat输出格式: %user %nice %system %iowait %steal %idle
                try:
                    idle = float(parts[-1])  # 最后一列是idle
                    cpu_usage = 100.0 - idle
                    return max(0.0, min(100.0, cpu_usage))
                except ValueError:
                    pass
        
        raise Exception(f"iostat failed: code={code}, stdout='{stdout}'")

# 使用示例
def demo_usage():
    """演示如何使用CPU使用率获取助手"""
    from unittest.mock import Mock
    
    # 创建模拟节点
    mock_node = Mock()
    
    def mock_execute(command):
        # 模拟不同的返回结果
        if "top -bn1" in command and "head -10" in command:
            return "%Cpu(s): 25.3 us,  2.1 sy,  0.0 ni, 72.1 id,  0.4 wa,  0.0 hi,  0.1 si,  0.0 st", "", 0
        elif "vmstat" in command:
            return "procs memory swap io system cpu\n 1 0 0 4096000 256000 2048000 0 0 5 10 100 200 25 3 71 1 0", "", 0
        else:
            return "", "Command not found", 127
    
    mock_node.execute = mock_execute
    
    # 测试CPU获取
    cpu_helper = CPUUsageHelper()
    cpu_usage = cpu_helper.get_cpu_usage(mock_node)
    print(f"获取到的CPU使用率: {cpu_usage}%")

if __name__ == "__main__":
    demo_usage()
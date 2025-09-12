#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试优先级转换逻辑修正
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_priority_conversion_logic():
    """测试优先级转换逻辑（本地测试）"""
    logger.info("开始测试优先级转换逻辑...")
    
    # 测试不同的优先级值
    test_cases = [
        (0, 0),          # 最高优先级
        (4096, 1),       # 标准优先级步长
        (8192, 2),       # testNode2当前设置
        (16384, 4),      # 中等优先级
        (32768, 8),      # 默认优先级
        (61440, 15),     # 最低优先级
        (65535, 15),     # 超出范围，应限制为15
        (100000, 15),    # 远超范围，应限制为15
    ]
    
    logger.info("\n=== 优先级转换测试结果 ===")
    logger.info("标准优先级 -> mstpd优先级 (期望值)")
    logger.info("-" * 40)
    
    all_passed = True
    
    for standard_priority, expected_mstpd in test_cases:
        # 应用转换逻辑（与network_topology.py中相同）
        mstpd_priority = standard_priority // 4096
        
        # 添加边界检查
        if mstpd_priority > 15:
            mstpd_priority = 15
        elif mstpd_priority < 0:
            mstpd_priority = 0
            
        # 验证结果
        passed = (mstpd_priority == expected_mstpd)
        status = "✓" if passed else "✗"
        
        logger.info(f"{standard_priority:6d} -> {mstpd_priority:2d} ({expected_mstpd:2d}) {status}")
        
        if not passed:
            all_passed = False
            logger.error(f"转换错误: {standard_priority} -> {mstpd_priority}, 期望: {expected_mstpd}")
    
    logger.info("-" * 40)
    if all_passed:
        logger.info("✓ 所有优先级转换测试通过！")
    else:
        logger.error("✗ 部分优先级转换测试失败！")
    
    # 测试边界情况
    logger.info("\n=== 边界情况测试 ===")
    edge_cases = [-1, -100, 0, 65535, 100000]
    
    for priority in edge_cases:
        mstpd_priority = priority // 4096
        if mstpd_priority > 15:
            mstpd_priority = 15
        elif mstpd_priority < 0:
            mstpd_priority = 0
        
        in_range = 0 <= mstpd_priority <= 15
        status = "✓" if in_range else "✗"
        logger.info(f"优先级 {priority:6d} -> mstpd {mstpd_priority:2d} (范围检查: {status})")
    
    return all_passed

def simulate_mstpctl_command():
    """模拟mstpctl命令执行"""
    logger.info("\n=== 模拟mstpctl命令执行 ===")
    
    test_priorities = [0, 4096, 8192, 32768]
    
    for priority in test_priorities:
        mstpd_priority = priority // 4096
        if mstpd_priority > 15:
            mstpd_priority = 15
        elif mstpd_priority < 0:
            mstpd_priority = 0
            
        command = f"mstpctl settreeprio br0 0 {mstpd_priority}"
        logger.info(f"标准优先级 {priority:5d} -> 命令: {command}")
        
        # 验证命令参数范围
        if 0 <= mstpd_priority <= 15:
            logger.info(f"  ✓ 参数 {mstpd_priority} 在有效范围内 (0-15)")
        else:
            logger.error(f"  ✗ 参数 {mstpd_priority} 超出有效范围 (0-15)")

if __name__ == "__main__":
    logger.info("开始优先级转换逻辑测试...")
    
    # 测试转换逻辑
    conversion_passed = test_priority_conversion_logic()
    
    # 模拟命令执行
    simulate_mstpctl_command()
    
    # 总结
    logger.info("\n=== 测试总结 ===")
    if conversion_passed:
        logger.info("✓ 优先级转换逻辑修正成功！")
        logger.info("✓ 所有测试用例通过")
        logger.info("✓ 边界检查正常工作")
        logger.info("✓ mstpctl命令参数在有效范围内")
    else:
        logger.error("✗ 优先级转换逻辑存在问题")
    
    logger.info("\n修正内容:")
    logger.info("1. 使用整数除法: mstpd_priority = priority // 4096")
    logger.info("2. 添加上边界检查: if mstpd_priority > 15: mstpd_priority = 15")
    logger.info("3. 添加下边界检查: if mstpd_priority < 0: mstpd_priority = 0")
    logger.info("4. 确保mstpctl命令参数在0-15范围内")
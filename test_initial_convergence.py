#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
初始收敛时间测试脚本
专门用于测量从拓扑创建到完全收敛需要的时间
"""

import time
import logging
import yaml
from pathlib import Path
from src.ssh_manager import SSHManager
from src.network_topology import NetworkTopology
from src.rstp_analyzer import RSTPAnalyzer
import pytest

class InitialConvergenceMonitor:
    def __init__(self, timeout=900):  # 15分钟超时
        self.timeout = timeout
        self.logger = logging.getLogger("InitialConvergenceMonitor")
        # 添加更细粒度的配置
        self.detection_interval = 0.1  # 100ms 检测间隔
        self.convergence_check_interval = 0.5  # 500ms 收敛检查间隔
        
    def wait_for_convergence(self, analyzers, timeout=None):
        """等待网络收敛"""
        timeout = timeout or self.timeout
        start_time = time.time()
        
        self.logger.info(f"开始等待收敛，超时时间: {timeout}秒")
        
        # 记录每次检查的状态
        check_count = 0
        last_log_time = start_time
        
        while time.time() - start_time < timeout:
            check_count += 1
            current_time = time.time()
            elapsed_time = current_time - start_time
            
            # 每30秒记录一次进度
            if current_time - last_log_time >= 30:
                self.logger.info(f"收敛检查进度: {elapsed_time:.1f}秒 (检查次数: {check_count})")
                last_log_time = current_time
            
            converged = True
            for analyzer in analyzers:
                try:
                    # 获取当前状态
                    bridge_info = analyzer.get_bridge_info()
                    if not self._is_stable_state(bridge_info):
                        converged = False
                        self.logger.debug(f"网络尚未收敛，继续等待... (已等待 {elapsed_time:.1f}秒)")
                        break
                except Exception as e:
                    self.logger.debug(f"检查收敛状态时出错: {e}")
                    converged = False
                    break
            
            if converged:
                convergence_time = time.time() - start_time
                self.logger.info(f"网络已收敛！耗时: {convergence_time:.2f}秒 (检查次数: {check_count})")
                return convergence_time
            
            time.sleep(self.convergence_check_interval)
        
        # 超时
        elapsed_time = time.time() - start_time
        self.logger.warning(f"收敛检测超时: {elapsed_time:.2f}秒 (检查次数: {check_count})")
        return elapsed_time
    
    def _is_stable_state(self, bridge_info):
        """判断桥接状态是否稳定"""
        for port_name, port_info in bridge_info.ports.items():
            state = port_info.get('state', 'UNKNOWN')
            role = port_info.get('role', 'UNKNOWN')
            
            # 根据RSTP标准定义稳定状态
            if state == 'DISABLED':
                continue  # DISABLED状态总是稳定的
            elif state == 'BLOCKING':
                continue  # BLOCKING状态总是稳定的
            elif state == 'LISTENING':
                self.logger.debug(f"端口 {port_name} 处于LISTENING状态，不稳定")
                return False  # LISTENING状态不稳定
            elif state == 'LEARNING':
                self.logger.debug(f"端口 {port_name} 处于LEARNING状态，不稳定")
                return False  # LEARNING状态不稳定
            elif state == 'FORWARDING':
                if role not in ['ROOT', 'DESIGNATED']:
                    self.logger.debug(f"端口 {port_name} 处于FORWARDING状态但角色为 {role}，不稳定")
                    return False  # FORWARDING状态只有ROOT和DESIGNATED角色稳定
            elif state == 'DISCARDING':
                # DISCARDING状态在ALTERNATE、BACKUP、DISABLED角色时稳定
                if role not in ['ALTERNATE', 'BACKUP', 'DISABLED']:
                    self.logger.debug(f"端口 {port_name} 处于DISCARDING状态但角色为 {role}，不稳定")
                    return False
        
        return True

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'logs/initial_convergence_test_{time.strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_config():
    """加载配置文件"""
    config_path = Path(__file__).parent / 'config.yaml'
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def test_initial_convergence(convergence_monitor):
    """测试初始收敛时间"""
    logger.info("开始初始收敛时间测试...")
    
    # 加载配置
    config = load_config()
    
    # 创建SSH管理器
    dut_ssh = SSHManager(
        "DUT",
        config['vms']['dut']['ip'],
        config['vms']['dut']['username'],
        config['vms']['dut']['password']
    )
    
    testnode1_ssh = SSHManager(
        "TestNode1",
        config['vms']['nodes'][0]['ip'],
        config['vms']['nodes'][0]['username'],
        config['vms']['nodes'][0]['password']
    )
    
    testnode2_ssh = SSHManager(
        "TestNode2",
        config['vms']['nodes'][1]['ip'],
        config['vms']['nodes'][1]['username'],
        config['vms']['nodes'][1]['password']
    )
    
    try:
        # 创建拓扑管理器
        topology = NetworkTopology([dut_ssh, testnode1_ssh, testnode2_ssh])
        
        # 创建分析器
        dut_analyzer = RSTPAnalyzer(dut_ssh)
        
        # 使用pytest fixture提供的收敛监控器（多SSH会话并行监控）
        convergence_monitor.timeout = 900  # 设置15分钟超时
        
        logger.info("=== 第1步：创建拓扑 ===")
        start_time = time.time()
        topology.create_ring_topology(use_rstp=True)
        topology_time = time.time() - start_time
        logger.info(f"拓扑创建完成，耗时: {topology_time:.2f}秒")
        
        logger.info("=== 第2步：等待初始收敛（多SSH会话并行监控）===")
        analyzers = [dut_analyzer]
        initial_convergence_time = convergence_monitor.wait_for_convergence(analyzers)
        
        # 输出测试结果
        logger.info("============================================================")
        logger.info("初始收敛时间测试结果:")
        logger.info(f"拓扑创建时间: {topology_time:.2f}秒")
        logger.info(f"初始收敛时间: {initial_convergence_time:.2f}秒")
        logger.info(f"总时间: {topology_time + initial_convergence_time:.2f}秒")
        
        if initial_convergence_time < convergence_monitor.timeout:
            logger.info("✅ 初始收敛测试成功")
            logger.info(f"建议的超时设置: {max(600, int(initial_convergence_time * 1.5))}秒")
        else:
            logger.error("❌ 初始收敛测试超时")
            logger.error(f"当前超时设置: {convergence_monitor.timeout}秒")
            logger.error("建议增加超时时间或检查网络配置")
        
        logger.info("============================================================")
        
        return initial_convergence_time < convergence_monitor.timeout
        
    except Exception as e:
        logger.error(f"测试过程中发生错误: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False
    
    finally:
        # 清理资源
        try:
            dut_ssh.close()
            testnode1_ssh.close()
            testnode2_ssh.close()
        except:
            pass

if __name__ == "__main__":
    success = test_initial_convergence()
    exit(0 if success else 1)
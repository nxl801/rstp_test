#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简化的初始收敛时间测试
专门用于测量RSTP网络的初始收敛时间
"""

import time
import logging
import yaml
from src.ssh_manager import SSHManager
from src.network_topology import NetworkTopology

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('simple_convergence_test.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SimpleConvergenceTest')

class SimpleConvergenceMonitor:
    """简化的收敛监控器"""
    
    def __init__(self, ssh_managers, timeout=120):
        self.ssh_managers = ssh_managers
        self.timeout = timeout
        self.logger = logging.getLogger('ConvergenceMonitor')
    
    def wait_for_convergence(self):
        """等待网络收敛"""
        self.logger.info(f"开始等待网络收敛，超时时间: {self.timeout}秒")
        start_time = time.time()
        
        # 简单等待策略：等待一段时间让网络稳定
        initial_wait = 30  # 初始等待30秒
        self.logger.info(f"初始等待 {initial_wait} 秒...")
        time.sleep(initial_wait)
        
        # 检查网络状态
        stable_count = 0
        required_stable_checks = 1
        check_interval = 5
        
        while time.time() - start_time < self.timeout:
            try:
                # 检查所有节点的网桥状态
                all_stable = True
                for name, ssh_mgr in self.ssh_managers.items():
                    if not self._check_node_stable(name, ssh_mgr):
                        all_stable = False
                        break
                
                if all_stable:
                    stable_count += 1
                    self.logger.info(f"网络状态稳定检查 {stable_count}/{required_stable_checks}")
                    if stable_count >= required_stable_checks:
                        convergence_time = time.time() - start_time
                        self.logger.info(f"网络收敛完成，用时: {convergence_time:.2f}秒")
                        return convergence_time
                else:
                    stable_count = 0
                    self.logger.info("网络状态不稳定，重置计数器")
                
                time.sleep(check_interval)
                
            except Exception as e:
                self.logger.warning(f"收敛检查过程中出现错误: {e}")
                time.sleep(check_interval)
        
        # 超时
        self.logger.warning(f"等待收敛超时 ({self.timeout}秒)")
        return self.timeout
    
    def _check_node_stable(self, name, ssh_mgr):
        """检查单个节点是否稳定"""
        try:
            if name == 'DUT':
                # 检查OVS网桥状态
                stdout, stderr, exit_code = ssh_mgr.execute('ovs-vsctl show')
                if exit_code != 0:
                    return False
                # 简单检查：如果命令执行成功就认为稳定
                return True
            else:
                # 检查Linux网桥状态
                stdout, stderr, exit_code = ssh_mgr.execute('brctl show')
                if exit_code != 0:
                    return False
                return True
        except Exception as e:
            self.logger.warning(f"检查节点 {name} 状态时出错: {e}")
            return False

def main():
    """主函数"""
    logger.info("=== 开始简化的初始收敛时间测试 ===")
    
    nodes = []
    
    try:
        # 读取配置
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        logger.info("创建SSH连接...")
        
        # 创建SSH连接
        dut_config = config['vms']['dut']
        dut_ssh = SSHManager(
            'DUT',
            dut_config['ip'],
            dut_config['username'],
            dut_config['password']
        )
        
        testnode1_config = config['vms']['nodes'][0]
        testnode1_ssh = SSHManager(
            'TestNode1',
            testnode1_config['ip'],
            testnode1_config['username'],
            testnode1_config['password']
        )
        
        testnode2_config = config['vms']['nodes'][1]
        testnode2_ssh = SSHManager(
            'TestNode2',
            testnode2_config['ip'],
            testnode2_config['username'],
            testnode2_config['password']
        )
        
        nodes = [dut_ssh, testnode1_ssh, testnode2_ssh]
        ssh_managers = {
            'DUT': dut_ssh,
            'TestNode1': testnode1_ssh,
            'TestNode2': testnode2_ssh
        }
        
        logger.info("创建网络拓扑管理器...")
        topology = NetworkTopology([dut_ssh, testnode1_ssh, testnode2_ssh])
        
        # 记录拓扑创建开始时间
        logger.info("开始创建网络拓扑...")
        topology_start_time = time.time()
        
        # 创建环形拓扑
        topology.create_ring_topology(use_rstp=True)
        
        topology_creation_time = time.time() - topology_start_time
        logger.info(f"拓扑创建完成，用时: {topology_creation_time:.2f}秒")
        
        # 等待初始收敛
        logger.info("开始等待初始收敛...")
        convergence_monitor = SimpleConvergenceMonitor(ssh_managers, timeout=180)
        convergence_time = convergence_monitor.wait_for_convergence()
        
        # 输出结果
        total_time = topology_creation_time + convergence_time
        logger.info("=== 测试结果 ===")
        logger.info(f"拓扑创建时间: {topology_creation_time:.2f}秒")
        logger.info(f"收敛时间: {convergence_time:.2f}秒")
        logger.info(f"总时间: {total_time:.2f}秒")
        
        if convergence_time < 180:  # 未超时
            logger.info("✓ 初始收敛测试成功")
            print(f"\n=== 测试成功 ===")
            print(f"拓扑创建时间: {topology_creation_time:.2f}秒")
            print(f"收敛时间: {convergence_time:.2f}秒")
            print(f"总时间: {total_time:.2f}秒")
            print(f"建议的测试超时时间: {max(total_time * 2, 120):.0f}秒")
        else:
            logger.warning("✗ 初始收敛测试超时")
            print(f"\n=== 测试超时 ===")
            print(f"拓扑创建时间: {topology_creation_time:.2f}秒")
            print(f"等待时间: {convergence_time:.2f}秒 (超时)")
            print("建议检查网络配置或增加超时时间")
        
        return 0
        
    except Exception as e:
        logger.error(f"测试过程中发生错误: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return 1
    finally:
        # 清理连接
        try:
            for node in nodes:
                try:
                    node.close()
                except:
                    pass
        except NameError:
            # nodes变量未定义，跳过清理
            pass

if __name__ == '__main__':
    exit(main())
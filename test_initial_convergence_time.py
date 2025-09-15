#!/usr/bin/env python3
"""
初始收敛时间测试脚本
专门测量从拓扑创建到完全收敛需要多长时间
"""

import time
import logging
import yaml
from datetime import datetime
from src.ssh_manager import SSHManager
from src.network_topology import NetworkTopology

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('initial_convergence_test.log'),
        logging.StreamHandler()
    ]
)

class SimpleConvergenceMonitor:
    """简化的收敛监控器"""
    
    def __init__(self, nodes, timeout=600):
        self.nodes = nodes
        self.timeout = timeout
        self.logger = logging.getLogger("ConvergenceMonitor")
    
    def wait_for_convergence(self):
        """等待收敛完成"""
        self.logger.info(f"开始等待收敛，超时时间: {self.timeout}秒")
        start_time = time.time()
        
        while time.time() - start_time < self.timeout:
            elapsed = time.time() - start_time
            self.logger.info(f"检查收敛状态... (已等待 {elapsed:.1f}秒)")
            
            if self._check_all_nodes_stable():
                convergence_time = time.time() - start_time
                self.logger.info(f"收敛完成！耗时: {convergence_time:.2f}秒")
                return True, convergence_time
            
            # 每10秒检查一次
            time.sleep(10)
        
        # 超时
        timeout_time = time.time() - start_time
        self.logger.warning(f"收敛超时！已等待: {timeout_time:.2f}秒")
        return False, timeout_time
    
    def _check_all_nodes_stable(self):
        """检查所有节点是否稳定"""
        stable_count = 0
        total_nodes = len(self.nodes)
        
        for node in self.nodes:
            try:
                if self._is_node_stable(node):
                    stable_count += 1
                    self.logger.debug(f"{node.config.name}: 稳定")
                else:
                    self.logger.debug(f"{node.config.name}: 未稳定")
            except Exception as e:
                self.logger.warning(f"检查{node.config.name}状态失败: {e}")
        
        self.logger.info(f"稳定节点: {stable_count}/{total_nodes}")
        return stable_count == total_nodes
    
    def _is_node_stable(self, node):
        """检查单个节点是否稳定"""
        try:
            bridge_name = "SE_ETH2" if node.config.name == "DUT" else "br0"
            
            if node.config.name == "DUT":
                # DUT使用OVS命令检查
                stdout, stderr, code = node.execute_as_root(f"ovs-appctl rstp/show {bridge_name}")
                if code != 0:
                    return False
                
                # 检查是否有端口处于学习状态
                if "learning" in stdout.lower() or "listening" in stdout.lower():
                    return False
                
                # 检查是否有forwarding或blocking端口
                return "forwarding" in stdout.lower() or "blocking" in stdout.lower()
            else:
                # TestNode使用mstpctl检查
                stdout, stderr, code = node.execute_sudo(f"mstpctl showbridge {bridge_name}")
                if code != 0:
                    return False
                
                # 检查端口状态
                stdout_ports, stderr_ports, code_ports = node.execute_sudo(f"mstpctl showport {bridge_name}")
                if code_ports != 0:
                    return False
                
                # 检查是否有端口处于学习状态
                if "learning" in stdout_ports.lower() or "listening" in stdout_ports.lower():
                    return False
                
                return "forwarding" in stdout_ports.lower() or "blocking" in stdout_ports.lower()
                
        except Exception as e:
            self.logger.warning(f"检查{node.config.name}稳定性失败: {e}")
            return False

def main():
    logger = logging.getLogger("InitialConvergenceTest")
    logger.info("=== 开始初始收敛时间测试 ===")
    
    try:
        # 读取配置
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # 创建SSH连接
        logger.info("创建SSH连接...")
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
        
        nodes = [dut_ssh, testnode1_ssh, testnode2_ssh]
        
        # 创建网络拓扑
        logger.info("创建网络拓扑管理器...")
        topology = NetworkTopology(nodes)
        
        # 记录开始时间
        total_start_time = time.time()
        
        # 第1步：创建拓扑
        logger.info("=== 第1步：创建拓扑 ===")
        topology_start_time = time.time()
        topology.create_ring_topology(use_rstp=True)
        topology_time = time.time() - topology_start_time
        logger.info(f"拓扑创建完成，耗时: {topology_time:.2f}秒")
        
        # 第2步：等待初始收敛
        logger.info("=== 第2步：等待初始收敛 ===")
        convergence_monitor = SimpleConvergenceMonitor(nodes, timeout=600)  # 10分钟超时
        
        convergence_start_time = time.time()
        converged, convergence_time = convergence_monitor.wait_for_convergence()
        
        total_time = time.time() - total_start_time
        
        # 输出结果
        logger.info("=== 测试结果 ===")
        logger.info(f"拓扑创建时间: {topology_time:.2f}秒")
        logger.info(f"收敛等待时间: {convergence_time:.2f}秒")
        logger.info(f"总耗时: {total_time:.2f}秒")
        logger.info(f"收敛状态: {'成功' if converged else '超时'}")
        
        if converged:
            logger.info("=== 建议的超时设置 ===")
            # 建议超时时间为实际时间的2-3倍
            suggested_timeout = max(int(convergence_time * 2.5), 60)
            logger.info(f"建议初始等待时间: {int(convergence_time + 30)}秒")
            logger.info(f"建议收敛超时时间: {suggested_timeout}秒")
            
            # 写入结果文件
            with open('convergence_time_results.txt', 'w') as f:
                f.write(f"初始收敛时间测试结果\n")
                f.write(f"测试时间: {datetime.now()}\n")
                f.write(f"拓扑创建时间: {topology_time:.2f}秒\n")
                f.write(f"收敛等待时间: {convergence_time:.2f}秒\n")
                f.write(f"总耗时: {total_time:.2f}秒\n")
                f.write(f"收敛状态: {'成功' if converged else '超时'}\n")
                f.write(f"建议初始等待时间: {int(convergence_time + 30)}秒\n")
                f.write(f"建议收敛超时时间: {suggested_timeout}秒\n")
            
            logger.info("结果已保存到 convergence_time_results.txt")
        else:
            logger.error("初始收敛测试失败，请检查网络配置")
            return 1
        
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
    
    return 0

if __name__ == "__main__":
    exit(main())
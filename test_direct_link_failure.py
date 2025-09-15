#!/usr/bin/env python3
"""
专门测试直接链路故障的脚本
验证修改后的收敛检测逻辑是否能正确处理链路故障场景
"""

import sys
import os
import time
import yaml
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ssh_manager import SSHManager
from src.network_topology import NetworkTopology
from src.rstp_analyzer import RSTPAnalyzer
from src.fault_injector import FaultInjector
# 直接定义ConvergenceMonitor类（从conftest.py复制）
class ConvergenceMonitor:
    def __init__(self, timeout=None):
        # 设置默认超时时间为1500秒，以适应初始收敛需要的时间（基于测试观察，拓扑创建需要288秒，初始收敛需要超过300秒）
        self.timeout = timeout or 1500.0
        self.logger = logging.getLogger("ConvergenceMonitor")
        # 添加更细粒度的配置
        self.detection_interval = 0.005  # 5ms 检测间隔 - 更快检测
        self.detection_timeout = 20.0   # 设置为20秒检测窗口
        self.convergence_check_interval = 0.02  # 20ms 收敛检查间隔 - 更快检查
        # 添加物理链路状态检测缓存
        self._link_status_cache = {}
        self._last_link_check = 0
        
    def wait_for_convergence(self, analyzers, timeout=None):
        """等待网络收敛"""
        timeout = timeout or self.timeout
        start_time = time.time()
        
        self.logger.info(f"开始等待收敛，超时时间: {timeout}秒")
        
        while time.time() - start_time < timeout:
            converged = True
            for analyzer in analyzers:
                try:
                    # 获取当前状态
                    bridge_info = analyzer.get_bridge_info()
                    if not self._is_stable_state(bridge_info):
                        converged = False
                        break
                except Exception as e:
                    self.logger.debug(f"检查收敛状态时出错: {e}")
                    converged = False
                    break
            
            if converged:
                convergence_time = time.time() - start_time
                self.logger.info(f"网络已收敛，耗时: {convergence_time:.2f}秒")
                return convergence_time
            
            time.sleep(0.1)
        
        # 超时
        self.logger.warning(f"收敛检测超时: {timeout}秒")
        return timeout
    
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
                return False  # LISTENING状态不稳定
            elif state == 'LEARNING':
                return False  # LEARNING状态不稳定
            elif state == 'FORWARDING':
                if role not in ['ROOT', 'DESIGNATED']:
                    return False  # FORWARDING状态只有ROOT和DESIGNATED角色稳定
            elif state == 'DISCARDING':
                # DISCARDING状态在ALTERNATE、BACKUP、DISABLED角色时稳定
                if role not in ['ALTERNATE', 'BACKUP', 'DISABLED']:
                    return False
        
        return True
    
    def measure_convergence_with_ovs_wait(self, fault_function, analyzer, *args, **kwargs):
        """使用简化的收敛测量方法"""
        self.logger.info("开始故障收敛时间测量...")
        
        # 执行故障注入
        start_time = time.time()
        fault_function(*args, **kwargs)
        
        # 等待收敛
        convergence_time = self.wait_for_convergence([analyzer])
        
        return convergence_time
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'logs/direct_link_failure_test_{time.strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_config():
    """加载配置文件"""
    config_path = Path(__file__).parent / 'config.yaml'
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def test_direct_link_failure():
    """测试直接链路故障场景"""
    logger.info("开始直接链路故障测试...")
    
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
        
        # 创建故障注入器
        fault_injector = FaultInjector(dut_ssh)
        
        # 创建收敛监控器（使用更长的超时时间）
        convergence_monitor = ConvergenceMonitor(timeout=1500)  # 25分钟超时
        
        logger.info("=== 第1步：创建拓扑 ===")
        start_time = time.time()
        topology.create_ring_topology(use_rstp=True)
        topology_time = time.time() - start_time
        logger.info(f"拓扑创建完成，耗时: {topology_time:.2f}秒")
        
        logger.info("=== 第2步：等待初始收敛 ===")
        analyzers = [dut_analyzer]
        initial_convergence_time = convergence_monitor.wait_for_convergence(analyzers)
        logger.info(f"初始收敛时间: {initial_convergence_time:.2f}秒")
        
        if initial_convergence_time >= convergence_monitor.timeout:
            logger.error("初始收敛超时，无法继续测试")
            return False
        
        logger.info("=== 第3步：注入链路故障 ===")
        # 断开DUT的br4端口（连接到TestNode2）
        def inject_fault():
            fault_injector.link_down("br4")
            logger.info("已断开DUT的br4端口")
        
        # 测量故障后的收敛时间
        fault_convergence_time = convergence_monitor.measure_convergence_with_ovs_wait(
            inject_fault, dut_analyzer
        )
        
        logger.info(f"故障后收敛时间: {fault_convergence_time:.2f}秒")
        
        logger.info("=== 第4步：恢复链路 ===")
        def recover_fault():
            fault_injector.link_up("br4")
            logger.info("已恢复DUT的br4端口")
        
        # 测量恢复后的收敛时间
        recovery_convergence_time = convergence_monitor.measure_convergence_with_ovs_wait(
            recover_fault, dut_analyzer
        )
        
        logger.info(f"恢复后收敛时间: {recovery_convergence_time:.2f}秒")
        
        # 输出测试结果
        logger.info("============================================================")
        logger.info("直接链路故障测试结果:")
        logger.info(f"拓扑创建时间: {topology_time:.2f}秒")
        logger.info(f"初始收敛时间: {initial_convergence_time:.2f}秒")
        logger.info(f"故障后收敛时间: {fault_convergence_time:.2f}秒")
        logger.info(f"恢复后收敛时间: {recovery_convergence_time:.2f}秒")
        logger.info("============================================================")
        
        # 判断测试是否成功
        success = (
            initial_convergence_time < convergence_monitor.timeout and
            fault_convergence_time < 30.0 and  # 故障收敛应该在30秒内
            recovery_convergence_time < 30.0    # 恢复收敛应该在30秒内
        )
        
        if success:
            logger.info("🎉 直接链路故障测试通过！")
        else:
            logger.error("❌ 直接链路故障测试失败！")
            
        return success
        
    except Exception as e:
        logger.error(f"测试过程中发生错误: {e}")
        return False
    finally:
        # 清理资源
        try:
            topology.cleanup_topology()
        except:
            pass
        
        for ssh in [dut_ssh, testnode1_ssh, testnode2_ssh]:
            try:
                ssh.close()
            except:
                pass

if __name__ == "__main__":
    success = test_direct_link_failure()
    sys.exit(0 if success else 1)
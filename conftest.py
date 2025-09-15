"""
pytest配置文件和共享fixtures
"""

import os
import sys
import time
import yaml
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

import pytest

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.ssh_manager import SSHManager
from src.vmware_controller import VMwareController
from src.network_topology import NetworkTopology
from src.traffic_generator import TrafficGenerator
from src.rstp_analyzer import RSTPAnalyzer, PortState, PortRole
from src.fault_injector import FaultInjector
from utils.logger import setup_logging
from utils.reporter import TestReporter


# ==================== 配置加载 ====================

def load_config():
    """加载配置文件"""
    config_path = Path(__file__).parent / "config.yaml"
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


# ==================== pytest配置 ====================

def pytest_configure(config):
    """pytest配置钩子"""
    # 添加自定义标记
    config.addinivalue_line(
        "markers", "protocol_conformance: 协议一致性测试"
    )
    config.addinivalue_line(
        "markers", "convergence: 收敛测试"
    )
    config.addinivalue_line(
        "markers", "parameters: 参数配置测试"
    )
    config.addinivalue_line(
        "markers", "security: 安全性测试"
    )
    config.addinivalue_line(
        "markers", "high_availability: 高可用性测试"
    )
    config.addinivalue_line(
        "markers", "slow: 慢速测试"
    )

    # 设置日志
    setup_logging()


def pytest_collection_modifyitems(config, items):
    """修改测试项收集"""
    for item in items:
        # 自动为测试添加标记
        if "protocol" in item.nodeid:
            item.add_marker(pytest.mark.protocol_conformance)
        elif "convergence" in item.nodeid:
            item.add_marker(pytest.mark.convergence)
        elif "parameter" in item.nodeid:
            item.add_marker(pytest.mark.parameters)
        elif "security" in item.nodeid:
            item.add_marker(pytest.mark.security)
        elif "high_availability" in item.nodeid:
            item.add_marker(pytest.mark.high_availability)


# ==================== Session级别Fixtures ====================

@pytest.fixture(scope="session")
def test_config():
    """测试配置fixture"""
    return load_config()


@pytest.fixture(scope="session")
def vmware_controller(test_config):
    """VMware控制器fixture"""
    vmrun_path = test_config['test_environment']['vmware']['vmrun_path']
    try:
        return VMwareController(vmrun_path)
    except RuntimeError as e:
        pytest.skip(f"跳过需要VMware控制的测试: {e}")


@pytest.fixture(scope="session")
def logger():
    """日志fixture"""
    return logging.getLogger("RSTPTest")


# ==================== Module级别Fixtures ====================

@pytest.fixture(scope="module")
def dut_manager(test_config, logger):
    """DUT SSH管理器"""
    dut_config = test_config['vms']['dut']
    manager = SSHManager(
        name=dut_config['name'],
        ip=dut_config['ip'],
        username=dut_config['username'],
        password=dut_config['password']
    )

    # 连接DUT
    if manager.connect():
        logger.info(f"成功连接到DUT: {dut_config['name']}")
        yield manager
        manager.close()
    else:
        pytest.fail(f"无法连接到DUT: {dut_config['name']}")


@pytest.fixture(scope="module")
def test_nodes(test_config, logger):
    """测试节点SSH管理器列表"""
    nodes = []
    for node_config in test_config['vms']['nodes']:
        manager = SSHManager(
            name=node_config['name'],
            ip=node_config['ip'],
            username=node_config['username'],
            password=node_config['password']
        )
        if manager.connect():
            logger.info(f"成功连接到节点: {node_config['name']}")
            nodes.append(manager)
        else:
            logger.warning(f"无法连接到节点: {node_config['name']}")

    yield nodes

    # 清理
    for node in nodes:
        node.close()


@pytest.fixture(scope="module")
def network_topology(dut_manager, test_nodes):
    """网络拓扑管理器：包含DUT与测试节点"""
    nodes = [dut_manager] + test_nodes
    return NetworkTopology(nodes)
# ==================== Function级别Fixtures ====================

@pytest.fixture
def rstp_analyzer(dut_manager):
    """RSTP分析器"""
    return RSTPAnalyzer(dut_manager)

@pytest.fixture(scope="session")
def fault_injector():
    return FaultInjector()

@pytest.fixture
def traffic_generator(test_nodes):
    """流量生成器"""
    if len(test_nodes) >= 2:
        return TrafficGenerator(test_nodes[0], test_nodes[1])
    else:
        pytest.skip("需要至少2个测试节点进行流量测试")


@pytest.fixture(autouse=True)
def test_setup_teardown(request, logger):
    """每个测试的setup和teardown"""
    test_name = request.node.name
    logger.info(f"{'=' * 60}")
    logger.info(f"开始测试: {test_name}")
    logger.info(f"{'=' * 60}")

    start_time = time.time()

    yield

    duration = time.time() - start_time
    logger.info(f"测试完成: {test_name} (耗时: {duration:.2f}秒)")
    logger.info(f"{'=' * 60}\n")


@pytest.fixture
def convergence_monitor(test_config):
    """改进的收敛监控器"""

    class ConvergenceMonitor:
        def __init__(self, timeout=None):
            # 设置默认超时时间为1500秒，以适应初始收敛需要的时间（基于测试观察，拓扑创建需要293秒，初始收敛需要900秒）
            self.timeout = timeout or 1500.0
            self.logger = logging.getLogger("ConvergenceMonitor")
            # 添加更细粒度的配置
            self.detection_interval = 0.005  # 5ms 检测间隔 - 更快检测
            self.detection_timeout = 20.0   # 设置为20秒检测窗口
            self.convergence_check_interval = 0.02  # 20ms 收敛检查间隔 - 更快检查
            # 添加物理链路状态检测缓存
            self._link_status_cache = {}
            self._last_link_check = 0
            self.link_check_interval = 0.1  # 100ms 物理链路检查间隔
            
        def check_link_status(self, node, interface: str) -> str:
            """直接通过ip link命令检测物理链路状态"""
            try:
                # 构建缓存键
                cache_key = f"{node.config.name}:{interface}"
                current_time = time.time()
                
                # 检查缓存是否有效
                if (cache_key in self._link_status_cache and 
                    current_time - self._last_link_check < self.link_check_interval):
                    return self._link_status_cache[cache_key]
                
                # 执行ip link命令检测状态
                cmd = f"ip link show {interface} | grep -o 'state [A-Z]*'"
                stdout, stderr, code = node.execute(cmd)
                
                if code == 0 and stdout:
                    # 解析输出判断UP/DOWN状态
                    if 'state UP' in stdout:
                        status = 'UP'
                    elif 'state DOWN' in stdout:
                        status = 'DOWN'
                    else:
                        status = 'UNKNOWN'
                else:
                    # 备用方法：检查接口是否存在
                    cmd_alt = f"ip link show {interface}"
                    stdout_alt, _, code_alt = node.execute(cmd_alt)
                    if code_alt == 0:
                        # 接口存在但状态未知
                        status = 'EXISTS'
                    else:
                        # 接口不存在
                        status = 'NOT_EXISTS'
                
                # 更新缓存
                self._link_status_cache[cache_key] = status
                self._last_link_check = current_time
                
                self.logger.debug(f"物理链路状态 {node.config.name}:{interface} = {status}")
                return status
                
            except Exception as e:
                self.logger.warning(f"检测物理链路状态失败 {node.config.name}:{interface}: {e}")
                return 'ERROR'
        
        def verify_rstp_configuration(self, node, bridge: str = "br0") -> Dict[str, Any]:
            """验证RSTP配置 - 确保DUT确实在运行RSTP而不是STP"""
            verification_result = {
                'rstp_enabled': False,
                'stp_enabled': False,
                'bridge_exists': False,
                'method': 'unknown',
                'details': {}
            }
            
            try:
                # 对于DUT，使用SE_ETH2作为网桥名称
                if node.config.name == "DUT" and bridge == "br0":
                    bridge = "SE_ETH2"
                
                # 检查网桥是否存在
                bridge_check_cmd = f"ip link show {bridge}"
                stdout, stderr, code = node.execute(bridge_check_cmd)
                verification_result['bridge_exists'] = (code == 0)
                
                if not verification_result['bridge_exists']:
                    self.logger.warning(f"网桥 {bridge} 不存在于节点 {node.config.name}")
                    return verification_result
                
                # 检测RSTP配置方法
                if node.config.name == "DUT":
                    # DUT使用OVS方法
                    verification_result['method'] = 'ovs'
                    
                    # 检查OVS RSTP配置
                    rstp_cmd = f"ovs-vsctl get Bridge {bridge} rstp_enable"
                    stdout, stderr, code = node.execute(rstp_cmd)
                    if code == 0 and 'true' in stdout.lower():
                        verification_result['rstp_enabled'] = True
                        verification_result['details']['ovs_rstp'] = 'enabled'
                    else:
                        verification_result['details']['ovs_rstp'] = 'disabled'
                    
                    # 检查其他OVS RSTP参数
                    for param in ['rstp-priority', 'rstp-hello-time', 'rstp-forward-delay', 'rstp-max-age']:
                        param_cmd = f"ovs-vsctl get Bridge {bridge} other_config:{param}"
                        stdout, stderr, code = node.execute(param_cmd)
                        if code == 0:
                            verification_result['details'][param] = stdout.strip()
                else:
                    # TestNode使用mstpd或传统方法
                    # 检查mstpd
                    mstpd_cmd = "sudo systemctl is-active mstpd"
                    stdout, stderr, code = node.execute(mstpd_cmd)
                    if code == 0 and 'active' in stdout:
                        verification_result['method'] = 'mstpd'
                        verification_result['rstp_enabled'] = True
                        verification_result['details']['mstpd_status'] = 'active'
                    else:
                        # 检查传统STP
                        verification_result['method'] = 'legacy'
                        stp_cmd = f"brctl showstp {bridge}"
                        stdout, stderr, code = node.execute(stp_cmd)
                        if code == 0:
                            verification_result['stp_enabled'] = True
                            verification_result['details']['legacy_stp'] = 'enabled'
                
                self.logger.info(f"RSTP配置验证 {node.config.name}: {verification_result}")
                return verification_result
                
            except Exception as e:
                self.logger.error(f"RSTP配置验证失败 {node.config.name}: {e}")
                verification_result['details']['error'] = str(e)
                return verification_result
        
        def setup_ovs_event_monitoring(self, node, bridge: str = "SE_ETH2") -> bool:
            """设置OVS事件监听 - 用于实时检测RSTP状态变化"""
            try:
                if node.config.name != "DUT":
                    self.logger.debug(f"节点 {node.config.name} 不是DUT，跳过OVS事件监听设置")
                    return False
                
                # 检查OVS是否支持事件监听
                cmd = "ovs-appctl --help | grep -q 'ofproto/trace'"
                stdout, stderr, code = node.execute(cmd)
                if code != 0:
                    self.logger.warning("OVS不支持ofproto/trace，无法设置事件监听")
                    return False
                
                # 启用RSTP事件日志
                cmd = f"ovs-appctl vlog/set rstp:dbg"
                stdout, stderr, code = node.execute(cmd)
                if code == 0:
                    self.logger.info("已启用OVS RSTP调试日志")
                else:
                    self.logger.warning(f"启用RSTP调试日志失败: {stderr}")
                
                # 设置端口状态变化监听
                cmd = f"ovs-appctl vlog/set ofproto:dbg"
                stdout, stderr, code = node.execute(cmd)
                if code == 0:
                    self.logger.info("已启用OVS ofproto调试日志")
                else:
                    self.logger.warning(f"启用ofproto调试日志失败: {stderr}")
                
                return True
                
            except Exception as e:
                self.logger.error(f"设置OVS事件监听失败: {e}")
                return False
        
        def monitor_ovs_events(self, node, bridge: str = "SE_ETH2", timeout: float = 5.0) -> List[Dict[str, Any]]:
            """监听OVS事件 - 检测RSTP状态变化事件"""
            events = []
            
            try:
                if node.config.name != "DUT":
                    return events
                
                # 获取当前日志位置作为起始点
                cmd = "journalctl -u openvswitch-switch --lines=0 --show-cursor -q"
                stdout, stderr, code = node.execute(cmd)
                cursor_start = None
                if code == 0 and stdout:
                    for line in stdout.split('\n'):
                        if 'cursor:' in line:
                            cursor_start = line.split('cursor:')[-1].strip()
                            break
                
                start_time = time.time()
                
                # 监听指定时间内的日志变化
                while time.time() - start_time < timeout:
                    if cursor_start:
                        cmd = f"journalctl -u openvswitch-switch --after-cursor='{cursor_start}' --lines=50 -q"
                    else:
                        cmd = "journalctl -u openvswitch-switch --since='5 seconds ago' --lines=50 -q"
                    
                    stdout, stderr, code = node.execute(cmd)
                    
                    if code == 0 and stdout:
                        for line in stdout.split('\n'):
                            line = line.strip()
                            if not line:
                                continue
                            
                            # 检测RSTP相关事件
                            if any(keyword in line.lower() for keyword in 
                                   ['rstp', 'port state', 'topology change', 'root bridge']):
                                
                                event = {
                                    'timestamp': time.time(),
                                    'type': 'rstp_event',
                                    'message': line,
                                    'bridge': bridge
                                }
                                
                                # 解析具体事件类型
                                if 'port state' in line.lower():
                                    event['event_type'] = 'port_state_change'
                                elif 'topology change' in line.lower():
                                    event['event_type'] = 'topology_change'
                                elif 'root bridge' in line.lower():
                                    event['event_type'] = 'root_bridge_change'
                                else:
                                    event['event_type'] = 'rstp_general'
                                
                                events.append(event)
                                self.logger.debug(f"检测到OVS事件: {event['event_type']} - {line}")
                    
                    time.sleep(0.01)  # 10ms检查间隔
                
                return events
                
            except Exception as e:
                self.logger.warning(f"监听OVS事件失败: {e}")
                return events
        
        def detect_topology_change_with_ovs_events(self, node, bridge: str = "SE_ETH2", 
                                                   timeout: float = 2.0) -> Optional[Tuple[float, str]]:
            """使用OVS事件检测拓扑变化 - 更快速和准确的检测方法"""
            try:
                if node.config.name != "DUT":
                    return None
                
                # 设置事件监听
                if not self.setup_ovs_event_monitoring(node, bridge):
                    return None
                
                # 监听事件
                events = self.monitor_ovs_events(node, bridge, timeout)
                
                # 分析事件，找到最早的拓扑变化
                earliest_event = None
                earliest_time = float('inf')
                
                for event in events:
                    if event['event_type'] in ['port_state_change', 'topology_change', 'root_bridge_change']:
                        if event['timestamp'] < earliest_time:
                            earliest_time = event['timestamp']
                            earliest_event = event
                
                if earliest_event:
                    return (earliest_event['timestamp'], 
                           f"OVS事件检测: {earliest_event['event_type']} - {earliest_event['message']}")
                
                return None
                
            except Exception as e:
                self.logger.warning(f"OVS事件检测失败: {e}")
                return None

        def measure_fault_convergence(self, fault_function, analyzers: List[RSTPAnalyzer], *args, **kwargs) -> float:
            """测量故障收敛时间 - 优化版本，预先创建SSH会话后再故障注入"""
            self.logger.info("开始故障收敛时间测量...")
            
            # 预热：确保初始状态稳定
            initial_states = self._capture_topology_snapshot(analyzers)
            self.logger.debug(f"初始拓扑快照: {initial_states}")
            
            # 步骤1：预先创建所有SSH会话（避免在故障注入后创建导致时间不准确）
            self.logger.info("预先创建SSH会话以确保精确计时...")
            ssh_sessions_start = time.time()
            
            import threading
            import concurrent.futures
            from typing import Dict, Any
            
            # 为每个analyzer创建多个SSH连接
            def create_multiple_ssh_connections(analyzer: RSTPAnalyzer, num_sessions: int = 5) -> List[RSTPAnalyzer]:
                """为单个analyzer创建多个SSH会话"""
                ssh_analyzers = []
                for i in range(num_sessions):
                    try:
                        # 创建新的SSH连接
                        from src.ssh_manager import SSHManager
                        
                        # 直接使用SSHManager构造函数参数
                        new_ssh = SSHManager(
                            name=f"{analyzer.node.config.name}_session_{i}",
                            ip=analyzer.node.config.ip,
                            username=analyzer.node.config.username,
                            password=analyzer.node.config.password,
                            port=analyzer.node.config.port
                        )
                        # 确保新SSH对象有config属性，复制原始节点的config
                        new_ssh.config = analyzer.node.config
                        
                        if new_ssh.connect():
                            from src.rstp_analyzer import RSTPAnalyzer
                            new_analyzer = RSTPAnalyzer(new_ssh)
                            ssh_analyzers.append(new_analyzer)
                            self.logger.debug(f"成功创建SSH会话 {i} for {analyzer.node.config.name}")
                        else:
                            self.logger.warning(f"无法创建SSH会话 {i} for {analyzer.node.config.name}")
                    except Exception as e:
                        self.logger.warning(f"创建SSH会话 {i} 失败: {e}")
                
                return ssh_analyzers
            
            # 为所有analyzer创建多SSH会话
            all_ssh_analyzers = []
            for analyzer in analyzers:
                ssh_sessions = create_multiple_ssh_connections(analyzer)
                if ssh_sessions:
                    all_ssh_analyzers.extend(ssh_sessions)
                else:
                    # 如果无法创建新会话，使用原始analyzer
                    all_ssh_analyzers.append(analyzer)
            
            ssh_creation_time = time.time() - ssh_sessions_start
            self.logger.info(f"SSH会话创建完成: 总共创建了 {len(all_ssh_analyzers)} 个会话，耗时 {ssh_creation_time:.3f}s")
            
            # 步骤2：立即开始计时并执行故障注入
            fault_injection_start = time.time()
            start_time_str = time.strftime('%H:%M:%S', time.localtime(fault_injection_start))
            start_ms = int((fault_injection_start % 1) * 1000)
            self.logger.info(f"=== 故障注入开始时间: {start_time_str}.{start_ms:03d} (时间戳: {fault_injection_start:.6f}) ===")
            
            # 执行故障注入
            fault_function(*args, **kwargs)
            
            # 步骤3：使用预创建的SSH会话进行收敛监控
            convergence_time = self._wait_for_convergence_with_precreated_sessions(
                all_ssh_analyzers, fault_injection_start)
            
            # 清理SSH连接
            for ssh_analyzer in all_ssh_analyzers:
                try:
                    if hasattr(ssh_analyzer.node, 'client') and ssh_analyzer.node.client:
                        ssh_analyzer.node.client.close()
                except:
                    pass
            
            self.logger.info(f"故障收敛完整流程: SSH创建{ssh_creation_time:.3f}s + 收敛监控{convergence_time:.3f}s")
            
            return convergence_time

        def _wait_for_convergence_with_precreated_sessions(self, all_ssh_analyzers: List[RSTPAnalyzer], start_time: float) -> float:
            """使用预创建的SSH会话等待网络收敛"""
            self.logger.info(f"使用 {len(all_ssh_analyzers)} 个预创建SSH会话进行收敛监控...")
            
            import threading
            import concurrent.futures
            from typing import Dict, Any
            
            # 共享变量用于存储收敛结果
            convergence_result = {
                'converged': False,
                'convergence_time': None,
                'first_session': None,
                'final_state': None
            }
            result_lock = threading.Lock()
            
            def monitor_single_session(session_analyzer: RSTPAnalyzer, session_id: str) -> Dict[str, Any]:
                """单个SSH会话的监控函数 - 增强版本，详细记录br3和br4状态"""
                session_logger = logging.getLogger(f"Session_{session_id}")
                last_check_time = start_time
                stable_count = 0
                required_stable_checks = 1
                current_interval = 0.02  # 20ms检测间隔
                check_count = 0
                
                session_logger.info(f"=== 会话 {session_id} 开始监控 ===")
                session_logger.info(f"监控开始时间: {time.strftime('%H:%M:%S', time.localtime(start_time))}.{int((start_time % 1) * 1000):03d}")
                
                while time.time() - start_time < self.timeout:
                    # 检查是否已经有其他会话检测到收敛
                    with result_lock:
                        if convergence_result['converged']:
                            session_logger.info(f"会话 {session_id}: 其他会话已检测到收敛，退出监控 (检查了 {check_count} 次)")
                            return {'status': 'other_converged'}
                    
                    current_time = time.time()
                    
                    # 检测间隔控制
                    if current_time - last_check_time < current_interval:
                        time.sleep(0.001)
                        continue
                    
                    last_check_time = current_time
                    check_count += 1
                    
                    try:
                        # 检查收敛状态
                        converged = True
                        current_states = []
                        br3_status = "未检测到"
                        br4_status = "未检测到"
                        
                        info = session_analyzer.get_bridge_info()
                        
                        # 如果获取网桥信息失败，跳过此次检查
                        if not info or not info.ports:
                            session_logger.debug(f"会话 {session_id} [检查#{check_count}]: 无法获取网桥信息，跳过此次检查")
                            continue
                        
                        # 对于DUT节点，只检查相关的RSTP端口（br3、br4）
                        if session_analyzer.node.config.name.startswith("DUT"):
                            relevant_ports = {name: port for name, port in info.ports.items() 
                                            if name in ['br3', 'br4']}
                        else:
                            # 对于其他节点，只检查参与RSTP的端口
                            relevant_ports = {name: port for name, port in info.ports.items() 
                                            if (port.state and port.state.name != 'UNKNOWN' and 
                                                port.role and port.role.name != 'UNKNOWN' and
                                                not name.startswith(('8N10', 'docker', 'lo', 'virbr', 'veth')))}
                        
                        # 详细记录br3和br4的状态
                        for port_name, port_info in relevant_ports.items():
                            state = port_info.state.name if port_info.state else 'UNKNOWN'
                            role = port_info.role.name if port_info.role else 'UNKNOWN'
                            
                            port_status = f"{role}/{state}"
                            current_states.append(f"{port_name}:{port_status}")
                            
                            # 记录br3和br4的具体状态
                            if port_name == 'br3':
                                br3_status = port_status
                            elif port_name == 'br4':
                                br4_status = port_status
                            
                            # RSTP稳定状态判断
                            is_stable = (
                                state == 'DISABLED' or
                                (state == 'FORWARDING' and role in ['ROOT', 'DESIGNATED']) or
                                (state == 'DISCARDING' and role in ['ALTERNATE', 'BACKUP', 'DISABLED'])
                            )
                            
                            if not is_stable:
                                converged = False
                        
                        # 详细记录每次检查的结果
                        elapsed_time = current_time - start_time
                        session_logger.info(f"会话 {session_id} [检查#{check_count}] 时间:{elapsed_time:.3f}s - br3:{br3_status}, br4:{br4_status} - {'稳定' if converged else '未稳定'}")
                        
                        if converged:
                            stable_count += 1
                            session_logger.info(f"会话 {session_id} [检查#{check_count}]: 连续稳定次数 {stable_count}/{required_stable_checks}")
                            
                            if stable_count >= required_stable_checks:
                                # 检测到收敛，更新共享结果
                                with result_lock:
                                    if not convergence_result['converged']:
                                        convergence_result['converged'] = True
                                        convergence_result['convergence_time'] = current_time - start_time
                                        convergence_result['first_session'] = session_id
                                        convergence_result['final_state'] = ', '.join(current_states)
                                        convergence_result['detection_details'] = {
                                            'check_count': check_count,
                                            'br3_final': br3_status,
                                            'br4_final': br4_status,
                                            'detection_time': current_time,
                                            'start_time': start_time
                                        }
                                        
                                        session_logger.info(f"*** 会话 {session_id} 首先检测到收敛! ***")
                                        session_logger.info(f"检测详情: 总检查次数={check_count}, br3最终状态={br3_status}, br4最终状态={br4_status}")
                                        return {
                                            'status': 'converged',
                                            'time': current_time - start_time,
                                            'state': ', '.join(current_states),
                                            'check_count': check_count,
                                            'br3_status': br3_status,
                                            'br4_status': br4_status
                                        }
                        else:
                            stable_count = 0
                            session_logger.debug(f"会话 {session_id} [检查#{check_count}]: 重置稳定计数器")
                            
                    except Exception as e:
                        session_logger.warning(f"会话 {session_id} [检查#{check_count}] 检查状态时出错: {e}")
                        # SSH连接可能断开，尝试重连
                        try:
                            if not session_analyzer.node.is_connected():
                                session_logger.info(f"会话 {session_id}: SSH连接断开，尝试重连...")
                                session_analyzer.node.connect()
                        except Exception as reconnect_error:
                            session_logger.warning(f"会话 {session_id}: 重连失败: {reconnect_error}")
                        continue
                
                session_logger.info(f"会话 {session_id}: 监控超时 (总检查次数: {check_count})")
                return {'status': 'timeout', 'check_count': check_count}
            
            # 使用线程池并行执行所有SSH会话监控
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(all_ssh_analyzers)) as executor:
                # 提交所有监控任务
                future_to_session = {}
                for i, ssh_analyzer in enumerate(all_ssh_analyzers):
                    session_id = f"{ssh_analyzer.node.config.name.split('_session_')[0]}_{i}"
                    future = executor.submit(monitor_single_session, ssh_analyzer, session_id)
                    future_to_session[future] = session_id
                
                # 等待第一个会话检测到收敛或超时
                try:
                    for future in concurrent.futures.as_completed(future_to_session, timeout=self.timeout):
                        session_id = future_to_session[future]
                        try:
                            result = future.result()
                            if result.get('status') == 'converged':
                                # 找到收敛，取消其他任务
                                for f in future_to_session:
                                    if f != future:
                                        f.cancel()
                                break
                        except Exception as e:
                            self.logger.warning(f"会话 {session_id} 执行异常: {e}")
                            
                except concurrent.futures.TimeoutError:
                    self.logger.warning("所有SSH会话监控超时")
            
            # 返回结果 - 增强版本，详细记录计算过程
            if convergence_result['converged']:
                convergence_time = convergence_result['convergence_time']
                end_time = start_time + convergence_time
                
                # 详细的时间计算日志
                detection_details = convergence_result.get('detection_details', {})
                start_time_str = time.strftime('%H:%M:%S', time.localtime(start_time))
                start_ms = int((start_time % 1) * 1000)
                end_time_str = time.strftime('%H:%M:%S', time.localtime(end_time))
                end_ms = int((end_time % 1) * 1000)
                
                self.logger.info("=== 预创建SSH会话并行监控 - 收敛时间计算详情 ===")
                self.logger.info(f"监控开始时间: {start_time_str}.{start_ms:03d} (时间戳: {start_time:.6f})")
                self.logger.info(f"收敛检测时间: {end_time_str}.{end_ms:03d} (时间戳: {end_time:.6f})")
                self.logger.info(f"计算公式: 收敛时间 = 检测时间 - 开始时间")
                self.logger.info(f"计算过程: {end_time:.6f} - {start_time:.6f} = {convergence_time:.6f}s")
                self.logger.info(f"首先检测到收敛的会话: {convergence_result['first_session']}")
                
                if detection_details:
                    self.logger.info(f"该会话总检查次数: {detection_details['check_count']}")
                    self.logger.info(f"br3最终状态: {detection_details['br3_final']}")
                    self.logger.info(f"br4最终状态: {detection_details['br4_final']}")
                
                self.logger.info(f"最终网络状态: {convergence_result['final_state']}")
                self.logger.info(f"*** 最终收敛时间: {convergence_time:.3f}s ***")
                self.logger.info("======================================================")
                return convergence_time
            else:
                end_time = time.time()
                total_elapsed = end_time - start_time
                start_time_str = time.strftime('%H:%M:%S', time.localtime(start_time))
                start_ms = int((start_time % 1) * 1000)
                end_time_str = time.strftime('%H:%M:%S', time.localtime(end_time))
                end_ms = int((end_time % 1) * 1000)
                
                self.logger.warning("=== 预创建SSH会话并行监控 - 收敛检测超时 ===")
                self.logger.warning(f"监控开始时间: {start_time_str}.{start_ms:03d}")
                self.logger.warning(f"监控结束时间: {end_time_str}.{end_ms:03d}")
                self.logger.warning(f"总监控时长: {total_elapsed:.3f}s (超时阈值: {self.timeout}s)")
                self.logger.warning(f"所有会话均未检测到收敛")
                self.logger.warning("===================================================")
                return self.timeout

        def _capture_topology_snapshot(self, analyzers: List[RSTPAnalyzer]) -> Dict:
            """捕获当前拓扑快照 - 增强版包含物理链路状态检测"""
            snapshot = {
                'timestamp': time.time(),
                'analyzers': {},
                'physical_links': {},
                'rstp_verification': {}
            }
            
            for i, analyzer in enumerate(analyzers):
                try:
                    info = analyzer.get_bridge_info()
                    node = analyzer.node
                    
                    # 验证RSTP配置
                    rstp_verification = self.verify_rstp_configuration(node)
                    snapshot['rstp_verification'][i] = rstp_verification
                    
                    snapshot['analyzers'][i] = {
                        'root_id': str(info.root_id) if info.root_id else None,
                        'bridge_id': str(info.bridge_id) if info.bridge_id else None,
                        'ports': {},
                        'physical_interfaces': {}
                    }
                    
                    for port_name, port_info in info.ports.items():
                        snapshot['analyzers'][i]['ports'][port_name] = {
                            'state': port_info.state.name if port_info.state else 'UNKNOWN',
                            'role': port_info.role.name if port_info.role else 'UNKNOWN',
                            'cost': port_info.path_cost
                        }
                        # 特别标记根端口
                        if port_info.role and port_info.role.name == 'ROOT':
                            snapshot['analyzers'][i]['root_port'] = port_name
                        
                        # 检测物理链路状态
                        link_status = self.check_link_status(node, port_name)
                        snapshot['analyzers'][i]['physical_interfaces'][port_name] = link_status
                        snapshot['physical_links'][f"{node.config.name}:{port_name}"] = link_status
                            
                except Exception as e:
                    self.logger.warning(f"捕获分析器{i}快照失败: {e}")
                    snapshot['analyzers'][i] = {'error': str(e)}
            
            return snapshot

        def _capture_topology_snapshot_nodes(self, nodes: List) -> Dict[str, Any]:
            """捕获节点拓扑快照 - 增强版包含物理链路状态检测"""
            import json
            import hashlib
            import re
            
            snapshot = {
                'timestamp': time.time(),
                'nodes': {},
                'root_bridge': None,
                'topology_hash': None,
                'physical_links': {},  # 新增：物理链路状态
                'rstp_verification': {}  # 新增：RSTP配置验证
            }
            
            for node in nodes:
                node_info = {
                    'bridge_id': None,
                    'root_id': None,
                    'ports': {},
                    'is_root': False,
                    'physical_interfaces': {}  # 新增：物理接口状态
                }
                
                try:
                    # 验证RSTP配置
                    rstp_verification = self.verify_rstp_configuration(node)
                    snapshot['rstp_verification'][node.config.name] = rstp_verification
                    
                    # 获取网桥信息
                    if hasattr(node, 'config') and node.config.name == "DUT":
                        # DUT使用OVS命令
                        bridge_name = "SE_ETH2"
                        cmd = f"ovs-vsctl get Bridge {bridge_name} other_config:stp-system-id"
                        stdout, stderr, code = node.execute(cmd)
                        if code == 0:
                            node_info['bridge_id'] = stdout.strip().strip('"')
                        
                        # 获取根网桥ID
                        cmd = f"ovs-appctl rstp/show {bridge_name}"
                        stdout, stderr, code = node.execute(cmd)
                        if code == 0:
                            for line in stdout.split('\n'):
                                if 'Root ID' in line:
                                    node_info['root_id'] = line.split(':')[-1].strip()
                                    break
                        
                        # 获取端口信息并检测物理链路状态
                        cmd = f"ovs-appctl rstp/show {bridge_name}"
                        stdout, stderr, code = node.execute(cmd)
                        if code == 0:
                            current_port = None
                            for line in stdout.split('\n'):
                                line = line.strip()
                                if line.startswith('Port'):
                                    port_match = re.search(r'Port (\S+)', line)
                                    if port_match:
                                        current_port = port_match.group(1)
                                        node_info['ports'][current_port] = {
                                            'role': 'unknown',
                                            'state': 'unknown',
                                            'cost': 0
                                        }
                                        # 检测物理链路状态
                                        link_status = self.check_link_status(node, current_port)
                                        node_info['physical_interfaces'][current_port] = link_status
                                        snapshot['physical_links'][f"{node.config.name}:{current_port}"] = link_status
                                elif current_port and 'Role:' in line:
                                    role = line.split('Role:')[-1].strip()
                                    node_info['ports'][current_port]['role'] = role
                                elif current_port and 'State:' in line:
                                    state = line.split('State:')[-1].strip()
                                    node_info['ports'][current_port]['state'] = state
                    else:
                        # TestNode使用mstpctl命令
                        bridge_name = "br0"
                        cmd = f"sudo mstpctl showbridge {bridge_name}"
                        stdout, stderr, code = node.execute(cmd)
                        if code == 0:
                            for line in stdout.split('\n'):
                                if 'bridge id' in line.lower():
                                    node_info['bridge_id'] = line.split()[-1]
                                elif 'designated root' in line.lower():
                                    node_info['root_id'] = line.split()[-1]
                        
                        # 获取端口信息并检测物理链路状态
                        cmd = f"sudo mstpctl showport {bridge_name}"
                        stdout, stderr, code = node.execute(cmd)
                        if code == 0:
                            for line in stdout.split('\n')[1:]:  # 跳过标题行
                                if line.strip():
                                    parts = line.split()
                                    if len(parts) >= 4:
                                        port_name = parts[0]
                                        role = parts[1]
                                        state = parts[2]
                                        node_info['ports'][port_name] = {
                                            'role': role,
                                            'state': state,
                                            'cost': 0
                                        }
                                        # 检测物理链路状态
                                        link_status = self.check_link_status(node, port_name)
                                        node_info['physical_interfaces'][port_name] = link_status
                                        snapshot['physical_links'][f"{node.config.name}:{port_name}"] = link_status
                    
                    # 检查是否为根网桥
                    if node_info['bridge_id'] and node_info['root_id']:
                        node_info['is_root'] = (node_info['bridge_id'] == node_info['root_id'])
                        if node_info['is_root']:
                            snapshot['root_bridge'] = node.config.name
                    
                except Exception as e:
                    self.logger.warning(f"获取节点 {node.config.name} 信息失败: {e}")
                
                snapshot['nodes'][node.config.name] = node_info
            
            # 生成拓扑哈希（包含物理链路状态）
            topology_data = {
                'nodes': snapshot['nodes'],
                'physical_links': snapshot['physical_links']
            }
            topology_str = json.dumps(topology_data, sort_keys=True)
            snapshot['topology_hash'] = hashlib.md5(topology_str.encode()).hexdigest()
            
            return snapshot

        def _detect_topology_change(self, analyzers: List[RSTPAnalyzer], initial_snapshot: Dict) -> Optional[Tuple[float, str]]:
            """检测拓扑变化，返回(检测时间, 变化描述) - 增强版包含物理链路检测"""
            try:
                current_snapshot = self._capture_topology_snapshot(analyzers)
                
                # 检查物理链路变化
                initial_links = initial_snapshot.get('physical_links', {})
                current_links = current_snapshot.get('physical_links', {})
                
                for link_key in initial_links:
                    if link_key in current_links:
                        if initial_links[link_key] != current_links[link_key]:
                            return (time.time(), f"物理链路状态变化 {link_key}: {initial_links[link_key]} -> {current_links[link_key]}")
                    else:
                        return (time.time(), f"物理链路消失: {link_key}")
                
                # 检查RSTP拓扑变化
                for i, analyzer in enumerate(analyzers):
                    if i not in initial_snapshot.get('analyzers', {}) or 'error' in initial_snapshot['analyzers'][i]:
                        continue
                    
                    if i not in current_snapshot.get('analyzers', {}) or 'error' in current_snapshot['analyzers'][i]:
                        continue
                    
                    initial = initial_snapshot['analyzers'][i]
                    current = current_snapshot['analyzers'][i]
                    
                    # 检查根网桥变化
                    if initial.get('root_id') != current.get('root_id'):
                        return (time.time(), f"节点{i}根网桥变化: {initial.get('root_id')} -> {current.get('root_id')}")
                    
                    # 检查端口变化
                    for port_name in initial.get('ports', {}):
                        if port_name not in current.get('ports', {}):
                            # 端口消失（可能是链路断开）
                            return (time.time(), f"节点{i}端口{port_name}消失")
                        
                        initial_port = initial['ports'][port_name]
                        current_port = current['ports'][port_name]
                        
                        # 检查角色变化（这是最重要的）
                        if initial_port['role'] != current_port['role']:
                            # 特别关注从ROOT或DESIGNATED变为其他角色
                            if initial_port['role'] in ['ROOT', 'DESIGNATED']:
                                return (time.time(), f"节点{i}端口{port_name}角色变化: {initial_port['role']} -> {current_port['role']}")
                        
                        # 检查状态变化（从FORWARDING变为其他状态）
                        if initial_port['state'] == 'FORWARDING' and current_port['state'] != 'FORWARDING':
                            return (time.time(), f"节点{i}端口{port_name}失去转发状态: {initial_port['state']} -> {current_port['state']}")
                        
                        # 检查DISABLED状态（链路物理断开）
                        if initial_port['state'] != 'DISABLED' and current_port['state'] == 'DISABLED':
                            return (time.time(), f"节点{i}端口{port_name}被禁用")
                
            except Exception as e:
                self.logger.debug(f"检测拓扑变化时出错: {e}")
            
            return None

        def measure_convergence_time(self, fault_function, analyzers: List[RSTPAnalyzer], 
                                    initial_snapshot: Dict = None, *args, **kwargs) -> Dict[str, Any]:
            """测量收敛时间 - 改进版本集成OVS事件监听"""
            self.logger.info("开始测量收敛时间（集成OVS事件监听）...")
            
            # 如果没有提供初始快照，现在捕获
            if initial_snapshot is None:
                initial_snapshot = self._capture_topology_snapshot(analyzers)
            
            # 设置OVS事件监听（仅对DUT节点）
            dut_node = None
            for analyzer in analyzers:
                if hasattr(analyzer, 'node') and analyzer.node.config.name == "DUT":
                    dut_node = analyzer.node
                    break
            
            ovs_monitoring_enabled = False
            if dut_node:
                ovs_monitoring_enabled = self.setup_ovs_event_monitoring(dut_node)
                if ovs_monitoring_enabled:
                    self.logger.info("OVS事件监听已启用")
                else:
                    self.logger.info("OVS事件监听不可用，使用传统轮询方式")
            
            # 执行故障注入
            fault_injection_time = time.time()
            self.logger.info(f"执行故障注入: {fault_function.__name__ if hasattr(fault_function, '__name__') else 'fault_function'}")
            
            # 在新线程中执行故障注入，避免阻塞检测
            import threading
            fault_thread = threading.Thread(target=lambda: fault_function(*args, **kwargs))
            fault_thread.start()
            
            # 检测拓扑变化 - 优先使用OVS事件监听
            detection_time = None
            change_description = None
            detection_start = time.time()
            
            # 如果启用了OVS事件监听，先尝试事件检测
            if ovs_monitoring_enabled and dut_node:
                self.logger.debug("尝试使用OVS事件检测拓扑变化")
                ovs_result = self.detect_topology_change_with_ovs_events(dut_node, timeout=2.0)
                if ovs_result:
                    detection_time, change_description = ovs_result
                    self.logger.info(f"OVS事件检测到拓扑变化: {change_description}")
            
            # 传统轮询检测作为备用或主要方法
            if not detection_time:
                while time.time() - detection_start < self.detection_timeout:
                    result = self._detect_topology_change(analyzers, initial_snapshot)
                    if result:
                        detection_time, change_description = result
                        break
                        
                    # 使用更短的检测间隔以提高精度
                    sleep_interval = 0.002 if ovs_monitoring_enabled else self.detection_interval
                    time.sleep(sleep_interval)
            
            # 等待故障注入线程完成
            fault_thread.join(timeout=1.0)
            
            # 记录检测结果
            if detection_time:
                actual_delay = detection_time - fault_injection_time
                detection_method = "OVS事件+轮询" if ovs_monitoring_enabled else "轮询"
                self.logger.info(f"检测到拓扑变化（{detection_method}）: {change_description}")
                self.logger.info(f"检测延迟: {actual_delay*1000:.1f}ms")
            else:
                detection_time = fault_injection_time
                actual_delay = 0
                self.logger.warning("未检测到明确的拓扑变化，使用故障注入时间作为基准")
            
            return {
                'fault_injection_time': fault_injection_time,
                'detection_time': detection_time,
                'measurement_start': detection_time,
                'detection_delay': actual_delay,
                'change_description': change_description,
                'ovs_monitoring_enabled': ovs_monitoring_enabled
            }

        def wait_for_convergence(self, analyzers: List[RSTPAnalyzer], start_time: float = None) -> float:
            """等待网络收敛 - 多SSH会话并行监控版本"""
            if start_time is None:
                start_time = time.time()
            
            self.logger.info(f"等待网络收敛 (最长{self.timeout}秒) - 使用多SSH会话并行监控...")
            
            import threading
            import concurrent.futures
            from typing import Dict, Any
            
            # 为每个analyzer创建多个SSH连接
            def create_multiple_ssh_connections(analyzer: RSTPAnalyzer, num_sessions: int = 5) -> List[RSTPAnalyzer]:
                """为单个analyzer创建多个SSH会话"""
                ssh_analyzers = []
                for i in range(num_sessions):
                    try:
                        # 创建新的SSH连接
                        from src.ssh_manager import SSHManager
                        
                        # 直接使用SSHManager构造函数参数
                        new_ssh = SSHManager(
                            name=f"{analyzer.node.config.name}_session_{i}",
                            ip=analyzer.node.config.ip,
                            username=analyzer.node.config.username,
                            password=analyzer.node.config.password,
                            port=analyzer.node.config.port
                        )
                        # 确保新SSH对象有config属性，复制原始节点的config
                        new_ssh.config = analyzer.node.config
                        
                        if new_ssh.connect():
                            from src.rstp_analyzer import RSTPAnalyzer
                            new_analyzer = RSTPAnalyzer(new_ssh)
                            ssh_analyzers.append(new_analyzer)
                            self.logger.debug(f"成功创建SSH会话 {i} for {analyzer.node.config.name}")
                        else:
                            self.logger.warning(f"无法创建SSH会话 {i} for {analyzer.node.config.name}")
                    except Exception as e:
                        self.logger.warning(f"创建SSH会话 {i} 失败: {e}")
                
                return ssh_analyzers
            
            # 为所有analyzer创建多SSH会话
            all_ssh_analyzers = []
            for analyzer in analyzers:
                ssh_sessions = create_multiple_ssh_connections(analyzer)
                if ssh_sessions:
                    all_ssh_analyzers.extend(ssh_sessions)
                else:
                    # 如果无法创建新会话，使用原始analyzer
                    all_ssh_analyzers.append(analyzer)
            
            self.logger.info(f"总共创建了 {len(all_ssh_analyzers)} 个SSH会话进行并行监控")
            
            # 共享变量用于存储收敛结果
            convergence_result = {
                'converged': False,
                'convergence_time': None,
                'first_session': None,
                'final_state': None
            }
            result_lock = threading.Lock()
            
            def monitor_single_session(session_analyzer: RSTPAnalyzer, session_id: str) -> Dict[str, Any]:
                """单个SSH会话的监控函数 - 增强版本，详细记录br3和br4状态"""
                session_logger = logging.getLogger(f"Session_{session_id}")
                last_check_time = start_time
                stable_count = 0
                required_stable_checks = 1
                current_interval = 0.1  # 100ms检测间隔
                check_count = 0
                
                session_logger.info(f"=== 会话 {session_id} 开始监控 ===")
                session_logger.info(f"监控开始时间: {time.strftime('%H:%M:%S', time.localtime(start_time))}.{int((start_time % 1) * 1000):03d}")
                
                while time.time() - start_time < self.timeout:
                    # 检查是否已经有其他会话检测到收敛
                    with result_lock:
                        if convergence_result['converged']:
                            session_logger.info(f"会话 {session_id}: 其他会话已检测到收敛，退出监控 (检查了 {check_count} 次)")
                            return {'status': 'other_converged'}
                    
                    current_time = time.time()
                    
                    # 检测间隔控制
                    if current_time - last_check_time < current_interval:
                        time.sleep(0.001)
                        continue
                    
                    last_check_time = current_time
                    check_count += 1
                    
                    try:
                        # 检查收敛状态
                        converged = True
                        current_states = []
                        br3_status = "未检测到"
                        br4_status = "未检测到"
                        
                        info = session_analyzer.get_bridge_info()
                        
                        # 如果获取网桥信息失败，跳过此次检查
                        if not info or not info.ports:
                            session_logger.debug(f"会话 {session_id} [检查#{check_count}]: 无法获取网桥信息，跳过此次检查")
                            continue
                        
                        # 对于DUT节点，只检查相关的RSTP端口（br3、br4）
                        if session_analyzer.node.config.name.startswith("DUT"):
                            relevant_ports = {name: port for name, port in info.ports.items() 
                                            if name in ['br3', 'br4']}
                        else:
                            # 对于其他节点，只检查参与RSTP的端口
                            relevant_ports = {name: port for name, port in info.ports.items() 
                                            if (port.state and port.state.name != 'UNKNOWN' and 
                                                port.role and port.role.name != 'UNKNOWN' and
                                                not name.startswith(('8N10', 'docker', 'lo', 'virbr', 'veth')))}
                        
                        # 详细记录br3和br4的状态
                        for port_name, port_info in relevant_ports.items():
                            state = port_info.state.name if port_info.state else 'UNKNOWN'
                            role = port_info.role.name if port_info.role else 'UNKNOWN'
                            
                            port_status = f"{role}/{state}"
                            current_states.append(f"{port_name}:{port_status}")
                            
                            # 记录br3和br4的具体状态
                            if port_name == 'br3':
                                br3_status = port_status
                            elif port_name == 'br4':
                                br4_status = port_status
                            
                            # RSTP稳定状态判断
                            is_stable = (
                                state == 'DISABLED' or
                                (state == 'FORWARDING' and role in ['ROOT', 'DESIGNATED']) or
                                (state == 'DISCARDING' and role in ['ALTERNATE', 'BACKUP', 'DISABLED'])
                            )
                            
                            if not is_stable:
                                converged = False
                        
                        # 详细记录每次检查的结果
                        elapsed_time = current_time - start_time
                        session_logger.info(f"会话 {session_id} [检查#{check_count}] 时间:{elapsed_time:.3f}s - br3:{br3_status}, br4:{br4_status} - {'稳定' if converged else '未稳定'}")
                        
                        if converged:
                            stable_count += 1
                            session_logger.info(f"会话 {session_id} [检查#{check_count}]: 连续稳定次数 {stable_count}/{required_stable_checks}")
                            
                            if stable_count >= required_stable_checks:
                                # 检测到收敛，更新共享结果
                                with result_lock:
                                    if not convergence_result['converged']:
                                        convergence_result['converged'] = True
                                        convergence_result['convergence_time'] = current_time - start_time
                                        convergence_result['first_session'] = session_id
                                        convergence_result['final_state'] = ', '.join(current_states)
                                        convergence_result['detection_details'] = {
                                            'check_count': check_count,
                                            'br3_final': br3_status,
                                            'br4_final': br4_status,
                                            'detection_time': current_time,
                                            'start_time': start_time
                                        }
                                        
                                        session_logger.info(f"*** 会话 {session_id} 首先检测到收敛! ***")
                                        session_logger.info(f"检测详情: 总检查次数={check_count}, br3最终状态={br3_status}, br4最终状态={br4_status}")
                                        return {
                                            'status': 'converged',
                                            'time': current_time - start_time,
                                            'state': ', '.join(current_states),
                                            'check_count': check_count,
                                            'br3_status': br3_status,
                                            'br4_status': br4_status
                                        }
                        else:
                            stable_count = 0
                            session_logger.debug(f"会话 {session_id} [检查#{check_count}]: 重置稳定计数器")
                            
                    except Exception as e:
                        session_logger.warning(f"会话 {session_id} [检查#{check_count}] 检查状态时出错: {e}")
                        # SSH连接可能断开，尝试重连
                        try:
                            if not session_analyzer.node.is_connected():
                                session_logger.info(f"会话 {session_id}: SSH连接断开，尝试重连...")
                                session_analyzer.node.connect()
                        except Exception as reconnect_error:
                            session_logger.warning(f"会话 {session_id}: 重连失败: {reconnect_error}")
                        continue
                
                session_logger.info(f"会话 {session_id}: 监控超时 (总检查次数: {check_count})")
                return {'status': 'timeout', 'check_count': check_count}
            
            # 使用线程池并行执行所有SSH会话监控
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(all_ssh_analyzers)) as executor:
                # 提交所有监控任务
                future_to_session = {}
                for i, ssh_analyzer in enumerate(all_ssh_analyzers):
                    session_id = f"{ssh_analyzer.node.config.name.split('_session_')[0]}_{i}"
                    future = executor.submit(monitor_single_session, ssh_analyzer, session_id)
                    future_to_session[future] = session_id
                
                # 等待第一个会话检测到收敛或超时
                try:
                    for future in concurrent.futures.as_completed(future_to_session, timeout=self.timeout):
                        session_id = future_to_session[future]
                        try:
                            result = future.result()
                            if result.get('status') == 'converged':
                                # 找到收敛，取消其他任务
                                for f in future_to_session:
                                    if f != future:
                                        f.cancel()
                                break
                        except Exception as e:
                            self.logger.warning(f"会话 {session_id} 执行异常: {e}")
                            
                except concurrent.futures.TimeoutError:
                    self.logger.warning("所有SSH会话监控超时")
            
            # 清理SSH连接
            for ssh_analyzer in all_ssh_analyzers:
                try:
                    if hasattr(ssh_analyzer.node, 'client') and ssh_analyzer.node.client:
                        ssh_analyzer.node.client.close()
                except:
                    pass
            
            # 返回结果 - 增强版本，详细记录计算过程
            if convergence_result['converged']:
                convergence_time = convergence_result['convergence_time']
                end_time = start_time + convergence_time
                
                # 详细的时间计算日志
                detection_details = convergence_result.get('detection_details', {})
                start_time_str = time.strftime('%H:%M:%S', time.localtime(start_time))
                start_ms = int((start_time % 1) * 1000)
                end_time_str = time.strftime('%H:%M:%S', time.localtime(end_time))
                end_ms = int((end_time % 1) * 1000)
                
                self.logger.info("=== 多SSH会话并行监控 - 收敛时间计算详情 ===")
                self.logger.info(f"监控开始时间: {start_time_str}.{start_ms:03d} (时间戳: {start_time:.6f})")
                self.logger.info(f"收敛检测时间: {end_time_str}.{end_ms:03d} (时间戳: {end_time:.6f})")
                self.logger.info(f"计算公式: 收敛时间 = 检测时间 - 开始时间")
                self.logger.info(f"计算过程: {end_time:.6f} - {start_time:.6f} = {convergence_time:.6f}s")
                self.logger.info(f"首先检测到收敛的会话: {convergence_result['first_session']}")
                
                if detection_details:
                    self.logger.info(f"该会话总检查次数: {detection_details['check_count']}")
                    self.logger.info(f"br3最终状态: {detection_details['br3_final']}")
                    self.logger.info(f"br4最终状态: {detection_details['br4_final']}")
                
                self.logger.info(f"最终网络状态: {convergence_result['final_state']}")
                self.logger.info(f"*** 最终收敛时间: {convergence_time:.3f}s ***")
                self.logger.info("================================================")
                return convergence_time
            else:
                end_time = time.time()
                total_elapsed = end_time - start_time
                start_time_str = time.strftime('%H:%M:%S', time.localtime(start_time))
                start_ms = int((start_time % 1) * 1000)
                end_time_str = time.strftime('%H:%M:%S', time.localtime(end_time))
                end_ms = int((end_time % 1) * 1000)
                
                self.logger.warning("=== 多SSH会话并行监控 - 收敛检测超时 ===")
                self.logger.warning(f"监控开始时间: {start_time_str}.{start_ms:03d}")
                self.logger.warning(f"监控结束时间: {end_time_str}.{end_ms:03d}")
                self.logger.warning(f"总监控时长: {total_elapsed:.3f}s (超时阈值: {self.timeout}s)")
                self.logger.warning(f"所有会话均未检测到收敛")
                self.logger.warning("============================================")
                return self.timeout

        def measure_convergence_with_ovs_wait(self, fault_function, analyzer: RSTPAnalyzer, *args, **kwargs) -> float:
            """使用ovs-vsctl wait来精确测量收敛时间"""
            self.logger.info("使用OVS事件监控进行收敛时间测量...")
            
            dut_node = analyzer.node
            bridge = "SE_ETH2"
            
            # 1. 启动一个后台线程来监听OVS事件
            import threading
            import subprocess
            
            # 我们需要监听所有端口的状态变化
            try:
                ports_to_monitor = list(analyzer.get_bridge_info(bridge).ports.keys())
            except Exception as e:
                self.logger.warning(f"无法获取端口信息，使用默认端口: {e}")
                ports_to_monitor = ["eth0", "eth2"]
            
            # 构造监听命令 - 监听RSTP拓扑变化
            monitor_cmd = f"ovs-vsctl --timeout={self.timeout} wait-until Bridge {bridge} rstp_status:topology_change=true"
            
            # 用于存储监听结果的变量
            monitor_result = {'completed': False, 'start_time': None, 'end_time': None}
            
            def monitor_ovs_events():
                """在后台监听OVS事件"""
                try:
                    monitor_result['start_time'] = time.time()
                    self.logger.debug(f"开始执行OVS监听命令: {monitor_cmd}")
                    
                    # 执行监听命令
                    result = dut_node.execute_as_root(monitor_cmd)
                    
                    monitor_result['end_time'] = time.time()
                    monitor_result['completed'] = True
                    self.logger.debug(f"OVS监听命令完成: {result}")
                    
                except Exception as e:
                    self.logger.warning(f"OVS监听过程中出错: {e}")
                    monitor_result['end_time'] = time.time()
                    monitor_result['completed'] = False
            
            # 在后台执行监听命令
            monitor_thread = threading.Thread(target=monitor_ovs_events)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # 确保监听已开始
            time.sleep(0.5)
            
            # 2. 触发故障并立即记录时间
            fault_injection_start_time = time.time()
            self.logger.info("执行故障注入...")
            
            try:
                fault_function(*args, **kwargs)
            except Exception as e:
                self.logger.error(f"故障注入失败: {e}")
                return -1.0
            
            # 3. 等待监控线程结束或超时
            monitor_thread.join(timeout=self.timeout)
            
            if monitor_result['completed'] and monitor_result['end_time']:
                # 使用OVS事件检测的时间
                convergence_time = monitor_result['end_time'] - fault_injection_start_time
                
                # 添加详细的收敛时间计算日志
                self.logger.info(f"=== OVS事件检测到收敛 ===")
                self.logger.info(f"故障注入时间: {time.strftime('%H:%M:%S', time.localtime(fault_injection_start_time))}.{int((fault_injection_start_time % 1) * 1000):03d}")
                self.logger.info(f"收敛完成时间: {time.strftime('%H:%M:%S', time.localtime(monitor_result['end_time']))}.{int((monitor_result['end_time'] % 1) * 1000):03d}")
                self.logger.info(f"总耗时: {convergence_time:.4f}秒")
                self.logger.info(f"=========================")
            else:
                # 如果OVS监听失败，回退到传统方法
                self.logger.warning("OVS事件监听失败，回退到传统轮询方法")
                
                # 使用传统的轮询方法检测收敛
                analyzers = [analyzer]
                convergence_start = time.time()
                last_unstable_reason = None  # 记录第一个导致未收敛判断的端口信息
                
                while time.time() - convergence_start < self.timeout:
                    converged = True
                    current_unstable_reason = None  # 当前检查轮次的不稳定原因
                    
                    try:
                        info = analyzer.get_bridge_info()
                        
                        # 对于DUT节点，只检查相关的RSTP端口（br3、br4）
                        if analyzer.node.config.name == "DUT":
                            # 只关注br3和br4端口，忽略其他管理接口和无关端口
                            relevant_ports = {name: port for name, port in info.ports.items() 
                                            if name in ['br3', 'br4']}
                        else:
                            # 对于其他节点，只检查参与RSTP的端口，排除管理接口和非RSTP端口
                            relevant_ports = {name: port for name, port in info.ports.items() 
                                            if (port.state and port.state != PortState.UNKNOWN and 
                                                port.role and port.role != PortRole.UNKNOWN and
                                                not name.startswith(('8N10', 'docker', 'lo', 'virbr', 'veth')))}
                        
                        for port_name, port_info in relevant_ports.items():
                            state = port_info.state.name if port_info.state else 'UNKNOWN'
                            role = port_info.role.name if port_info.role else 'UNKNOWN'
                            
                            # --- 核心修改：按照RSTP标准重新定义稳定状态判断条件 ---
                            # 根据RSTP标准，稳定状态包括：
                            # 1. Root角色 + FORWARDING状态 (通往根桥的最佳路径)
                            # 2. Designated角色 + FORWARDING状态 (网段中负责转发的端口)
                            # 3. Alternate角色 + DISCARDING状态 (根端口的备用路径)
                            # 4. Backup角色 + DISCARDING状态 (指定端口的备用路径)
                            # 5. DISABLED角色 + DISCARDING状态 (链路断开后的端口)
                            # 6. 任何角色 + DISABLED状态 (链路断开或管理员关闭)
                            # 过渡状态LEARNING和LISTENING不应被视为稳定状态
                            is_stable = (
                                state == 'DISABLED' or  # 任何角色的DISABLED都是稳定的
                                (state == 'FORWARDING' and role in ['ROOT', 'DESIGNATED']) or  # 只有Root/Designated的FORWARDING是稳定的
                                (state == 'DISCARDING' and role in ['ALTERNATE', 'BACKUP', 'DISABLED'])  # Alternate/Backup/DISABLED的DISCARDING是稳定的
                            )
                            
                            if not is_stable:
                                # 记录第一个导致未收敛判断的端口信息
                                if current_unstable_reason is None:
                                    current_unstable_reason = f"节点 {analyzer.node.config.name} 的端口 {port_name} 状态不稳定: {role}/{state}"
                                # 只要有一个端口状态不稳定，就认为未收敛
                                converged = False
                                break
                        
                        if converged:
                            end_time = time.time()
                            convergence_time = end_time - fault_injection_start_time
                            
                            # 添加详细的收敛时间计算日志
                            self.logger.info(f"=== 传统方法检测到收敛 ===")
                            self.logger.info(f"故障注入时间: {time.strftime('%H:%M:%S', time.localtime(fault_injection_start_time))}.{int((fault_injection_start_time % 1) * 1000):03d}")
                            self.logger.info(f"收敛完成时间: {time.strftime('%H:%M:%S', time.localtime(end_time))}.{int((end_time % 1) * 1000):03d}")
                            self.logger.info(f"总耗时: {convergence_time:.4f}秒")
                            self.logger.info(f"==========================")
                            break
                        
                        # 更新last_unstable_reason（只记录第一次出现的不稳定原因）
                        if not converged and last_unstable_reason is None:
                            last_unstable_reason = current_unstable_reason
                            
                    except Exception as e:
                        self.logger.debug(f"检查收敛状态时出错: {e}")
                        if current_unstable_reason is None:
                            current_unstable_reason = f"节点 {analyzer.node.config.name} 状态检查失败: {e}"
                        if last_unstable_reason is None:
                            last_unstable_reason = current_unstable_reason
                    
                    time.sleep(0.1)  # 更短的检测间隔
                else:
                    # 超时
                    convergence_time = self.timeout
                    self.logger.warning(f"收敛检测超时: {convergence_time}秒")
                    if last_unstable_reason:
                        self.logger.warning(f"超时原因: {last_unstable_reason}")
            
            return convergence_time

    return ConvergenceMonitor()


# ==================== 测试结果收集 ====================

@pytest.fixture(scope="session")
def test_results():
    """收集测试结果"""
    results = []
    yield results

    # 生成报告
    reporter = TestReporter("./reports")
    report_file = reporter.generate_report(results)
    print(f"\n测试报告已生成: {report_file}")


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """捕获测试结果"""
    outcome = yield
    report = outcome.get_result()

    if report.when == "call":
        # 保存测试结果
        if hasattr(item, "test_results"):
            item.test_results.append({
                'test_name': item.name,
                'outcome': report.outcome,
                'duration': report.duration,
                'timestamp': datetime.now().isoformat()
            })
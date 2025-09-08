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
from typing import Dict, List, Any

import pytest

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.ssh_manager import SSHManager
from src.vmware_controller import VMwareController
from src.network_topology import NetworkTopology
from src.traffic_generator import TrafficGenerator
from src.rstp_analyzer import RSTPAnalyzer
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


@pytest.fixture
def fault_injector(dut_manager):
    """故障注入器"""
    return FaultInjector(dut_manager)


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
    """收敛监控器"""

    class ConvergenceMonitor:
        def __init__(self, timeout=None):
            self.timeout = timeout or test_config['test_environment']['timeouts']['convergence']
            self.logger = logging.getLogger("ConvergenceMonitor")

        def wait_for_convergence(self, analyzers: List[RSTPAnalyzer]) -> float:
            """等待网络收敛"""
            start_time = time.time()
            self.logger.info(f"等待网络收敛 (最长{self.timeout}秒)...")

            while time.time() - start_time < self.timeout:
                converged = True
                for analyzer in analyzers:
                    info = analyzer.get_bridge_info()
                    for port_name, port_info in info.ports.items():
                        state = port_info.state.value.lower()
                        if state in ['learning', 'listening']:
                            converged = False
                            break
                    if not converged:
                        break

                if converged:
                    convergence_time = time.time() - start_time
                    self.logger.info(f"网络已收敛，耗时: {convergence_time:.2f}秒")
                    return convergence_time

                time.sleep(0.5)

            self.logger.warning(f"网络未能在{self.timeout}秒内收敛")
            return self.timeout

        def measure_convergence_time(self, fault_function, *args, **kwargs) -> Dict[str, Any]:
            """测量收敛时间"""
            self.logger.info("开始测量收敛时间...")

            # 记录故障注入时间
            fault_time = time.time()
            fault_function(*args, **kwargs)

            # 返回测量结果
            return {
                'fault_injection_time': fault_time,
                'measurement_start': time.time()
            }

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
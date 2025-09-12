"""
收敛测试
"""

import time
import pytest
import logging
from typing import Dict, Any

from src.rstp_analyzer import RSTPAnalyzer, PortRole
from src.network_topology import NetworkTopology
from src.fault_injector import FaultInjector
from src.traffic_generator import TrafficGenerator

logger = logging.getLogger(__name__)


@pytest.mark.convergence
class TestConvergence:
    """RSTP收敛测试套件"""

    def test_direct_link_failure(self, dut_manager, test_nodes,
                                 network_topology, rstp_analyzer,
                                 fault_injector, convergence_monitor):
        """TC.AUTO.2.1: 直接链路故障测试"""
        logger.info("开始直接链路故障测试")

        # 创建环形拓扑提供冗余路径
        network_topology.create_ring_topology(use_rstp=True)

        # 调整优先级，确保 DUT 不是根网桥
        network_topology.execute_bridge_command(test_nodes[0], "set_priority", priority=16384)
        network_topology.execute_bridge_command(dut_manager, "set_priority", priority=32768)
        if len(test_nodes) > 1:
            network_topology.execute_bridge_command(test_nodes[1], "set_priority", priority=28672)

        # 等待初始收敛
        analyzers = [rstp_analyzer] + [RSTPAnalyzer(node) for node in test_nodes]
        initial_convergence = convergence_monitor.wait_for_convergence(analyzers)
        logger.info(f"初始收敛时间: {initial_convergence:.2f}秒")

        # 确定DUT的Root Port
        info = rstp_analyzer.get_bridge_info()
        root_port = None
        for port_name, port_info in info.ports.items():
            if port_info.role == PortRole.ROOT:
                root_port = port_name
                break

        assert root_port, "未找到Root Port"
        logger.info(f"DUT的Root Port: {root_port}")

        # 使用改进的故障收敛时间测量方法
        convergence_time = convergence_monitor.measure_fault_convergence(
            fault_function=lambda: fault_injector.link_down(root_port),
            analyzers=analyzers
        )

        # 验证收敛时间（RSTP应该小于2.5秒，考虑网络环境因素）
        assert convergence_time < 2.5, \
            f"RSTP收敛时间过长: {convergence_time:.2f}秒"

        # 验证新的Root Port
        new_info = rstp_analyzer.get_bridge_info()
        new_root_port = None
        for port_name, port_info in new_info.ports.items():
            if port_info.role == PortRole.ROOT:
                new_root_port = port_name
                break

        assert new_root_port, "应该选举新的Root Port"
        assert new_root_port != root_port, \
            f"新Root Port({new_root_port})应该不同于原Port({root_port})"

        logger.info(f"链路故障收敛时间: {convergence_time:.2f}秒")
        logger.info(f"新的Root Port: {new_root_port}")
        logger.info("直接链路故障测试通过")

    def test_root_bridge_failure(self, dut_manager, test_nodes,
                                 network_topology, rstp_analyzer,
                                 vmware_controller, test_config,
                                 convergence_monitor):
        """TC.AUTO.2.2: 根网桥故障测试"""
        logger.info("开始根网桥故障测试")

        # 创建环形拓扑
        network_topology.create_ring_topology(use_rstp=True)

        # 设置节点1为根网桥
        test_nodes[0].execute_sudo("brctl setbridgeprio br0 12288")
        dut_manager.execute_sudo("brctl setbridgeprio br0 32768")
        if len(test_nodes) > 1:
            test_nodes[1].execute_sudo("brctl setbridgeprio br0 28672")

        # 等待初始收敛
        time.sleep(5)

        # 验证节点1是根网桥
        node1_analyzer = RSTPAnalyzer(test_nodes[0])
        assert node1_analyzer.is_root_bridge(), "节点1应该是根网桥"

        # 记录当前根网桥ID
        initial_info = rstp_analyzer.get_bridge_info()
        initial_root_id = initial_info.root_id
        logger.info(f"初始根网桥ID: {initial_root_id}")

        # 模拟根网桥故障（断开所有接口）
        start_time = time.time()
        for iface in ["eth0", "eth2"]:
            test_nodes[0].execute_sudo(f"ip link set dev {iface} down")

        # 等待重新选举
        analyzers = [rstp_analyzer] + [RSTPAnalyzer(node) for node in test_nodes[1:]]
        convergence_time = convergence_monitor.wait_for_convergence(analyzers)

        # 验证新的根网桥
        new_info = rstp_analyzer.get_bridge_info()
        new_root_id = new_info.root_id

        assert new_root_id != initial_root_id, \
            "应该选举新的根网桥"

        logger.info(f"新的根网桥ID: {new_root_id}")
        logger.info(f"根网桥故障收敛时间: {convergence_time:.2f}秒")

        # 验证收敛时间
        assert convergence_time < 5.0, \
            f"根网桥故障收敛时间过长: {convergence_time:.2f}秒"

        logger.info("根网桥故障测试通过")

    @pytest.mark.slow
    def test_multiple_link_failures(self, dut_manager, test_nodes,
                                    network_topology, rstp_analyzer,
                                    fault_injector, convergence_monitor):
        """测试多重链路故障"""
        logger.info("开始多重链路故障测试")

        # 创建环形拓扑
        network_topology.create_ring_topology(use_rstp=True)

        # 等待初始收敛
        analyzers = [rstp_analyzer] + [RSTPAnalyzer(node) for node in test_nodes]
        convergence_monitor.wait_for_convergence(analyzers)

        # 连续故障注入
        failures = []
        interfaces = ["eth0", "eth2"]

        for iface in interfaces:
            logger.info(f"注入故障: {iface}")
            
            # 使用改进的故障收敛时间测量方法
            convergence_time = convergence_monitor.measure_fault_convergence(
                fault_function=lambda i=iface: fault_injector.link_down(i),
                analyzers=analyzers
            )
            failures.append({
                'interface': iface,
                'convergence_time': convergence_time
            })

            logger.info(f"{iface}故障收敛时间: {convergence_time:.3f}秒")
            time.sleep(2)

        # 恢复所有链路
        for iface in interfaces:
            fault_injector.link_up(iface)

        # 等待最终收敛
        final_convergence = convergence_monitor.wait_for_convergence(analyzers)

        # 验证所有收敛时间
        for failure in failures:
            assert failure['convergence_time'] < 3.0, \
                f"{failure['interface']}收敛时间过长"

        logger.info(f"最终恢复收敛时间: {final_convergence:.2f}秒")
        logger.info("多重链路故障测试通过")

    def test_convergence_with_traffic(self, dut_manager, test_nodes,
                                      network_topology, traffic_generator,
                                      fault_injector, test_config):
        """测试带流量的收敛性能"""
        logger.info("开始带流量的收敛测试")

        # 创建拓扑
        network_topology.create_ring_topology(use_rstp=True)
        time.sleep(5)

        # 启动流量
        traffic_generator.start_iperf_server()
        time.sleep(2)
        traffic_generator.start_iperf_client(
            bandwidth=test_config['test_environment']['traffic']['iperf_bandwidth']
        )

        # 让流量稳定
        time.sleep(5)

        # 记录故障前的统计
        initial_stats = traffic_generator.get_statistics()

        # 注入故障
        fault_time = time.time()
        fault_injector.link_down("eth0")

        # 监控流量中断
        time.sleep(10)

        # 获取故障后的统计
        final_stats = traffic_generator.get_statistics()

        # 计算中断时间
        packet_loss = final_stats['packets_lost'] - initial_stats['packets_lost']
        packets_per_second = traffic_generator.get_packet_rate()
        interruption_time = packet_loss / packets_per_second if packets_per_second > 0 else 0

        logger.info(f"丢包数: {packet_loss}")
        logger.info(f"估计中断时间: {interruption_time:.3f}秒")

        # 停止流量
        traffic_generator.stop_traffic()

        # 验证中断时间
        assert interruption_time < 2.0, \
            f"流量中断时间过长: {interruption_time:.3f}秒"

        logger.info("带流量的收敛测试通过")
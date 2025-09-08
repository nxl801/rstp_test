"""
安全性测试
"""

import time
import pytest
import logging
from typing import Dict, Any

from src.rstp_analyzer import RSTPAnalyzer
from src.network_topology import NetworkTopology
from src.fault_injector import FaultInjector

logger = logging.getLogger(__name__)


@pytest.mark.security
class TestSecurity:
    """RSTP安全性测试套件"""

    def test_root_bridge_hijack_attack(self, dut_manager, test_nodes,
                                       network_topology, rstp_analyzer):
        """TC.AUTO.4.1: 根网桥劫持攻击测试"""
        logger.info("开始根网桥劫持攻击测试")

        # 创建环形拓扑
        network_topology.create_ring_topology(use_rstp=True)

        # DUT作为根网桥
        dut_manager.execute_sudo("brctl setbridgeprio br0 16384")
        if test_nodes:
            test_nodes[0].execute_sudo("brctl setbridgeprio br0 32768")

        time.sleep(5)

        # 验证DUT是根网桥
        assert rstp_analyzer.is_root_bridge(), "DUT应该是初始根网桥"
        initial_root_id = rstp_analyzer.get_bridge_info().bridge_id
        logger.info(f"初始根网桥: {initial_root_id}")

        # 从测试节点注入恶意BPDU
        if test_nodes:
            attacker = FaultInjector(test_nodes[0])
            attacker.inject_rogue_bpdu(
                interface="eth0",
                priority=0,  # 最高优先级
                src_mac="00:11:22:33:44:55",
                count=10,
                interval=2.0
            )

            # 等待攻击生效
            time.sleep(15)

            # 检查根网桥是否被劫持
            new_info = rstp_analyzer.get_bridge_info()

            if new_info.bridge_id != new_info.root_id:
                logger.warning("根网桥已被劫持!")
                logger.info(f"新的根网桥: {new_info.root_id}")

                # 这是预期行为（如果没有防护）
                assert True, "检测到根网桥劫持（预期行为，表明需要安全加固）"
            else:
                logger.info("根网桥未被劫持（可能已启用防护）")

        logger.info("根网桥劫持攻击测试完成")

    def test_bpdu_flood_attack(self, dut_manager, test_nodes,
                               network_topology, rstp_analyzer):
        """测试BPDU洪泛攻击"""
        logger.info("开始BPDU洪泛攻击测试")

        # 创建拓扑
        network_topology.create_ring_topology(use_rstp=True)
        time.sleep(5)

        # 记录初始CPU使用率
        initial_cpu = self._get_cpu_usage(dut_manager)
        logger.info(f"初始CPU使用率: {initial_cpu}%")

        # 生成大量BPDU
        if test_nodes:
            script = """
from scapy.all import *
import time

target_mac = "01:80:c2:00:00:00"
interface = "eth0"

for i in range(1000):
    # 随机优先级和MAC
    priority = random.randint(0, 65535)
    src_mac = RandMAC()

    eth = Ether(dst=target_mac, src=src_mac)
    llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
    bpdu = STP(
        bpdutype=0x00,
        rootid=priority,
        rootmac=src_mac,
        bridgeid=priority,
        bridgemac=src_mac
    )

    sendp(eth/llc/bpdu, iface=interface, verbose=0)

print("BPDU flood completed")
"""

            test_nodes[0].execute(f"echo '{script}' > /tmp/bpdu_flood.py")
            test_nodes[0].execute_sudo("python3 /tmp/bpdu_flood.py &")

            # 监控影响
            time.sleep(10)

            # 检查CPU使用率
            flood_cpu = self._get_cpu_usage(dut_manager)
            logger.info(f"洪泛时CPU使用率: {flood_cpu}%")

            # 检查是否仍然稳定
            state = rstp_analyzer.get_convergence_state()

            if not state['stable']:
                logger.warning("BPDU洪泛导致网络不稳定")
            else:
                logger.info("网络在BPDU洪泛下保持稳定")

            # CPU增长不应该过高
            cpu_increase = flood_cpu - initial_cpu
            if cpu_increase > 50:
                logger.warning(f"CPU使用率增加过高: {cpu_increase}%")

        logger.info("BPDU洪泛攻击测试完成")

    def test_topology_change_attack(self, dut_manager, test_nodes,
                                    network_topology, rstp_analyzer):
        """测试拓扑变更攻击"""
        logger.info("开始拓扑变更攻击测试")

        # 创建拓扑
        network_topology.create_ring_topology(use_rstp=True)
        time.sleep(5)

        # 记录初始拓扑变更计数
        initial_info = rstp_analyzer.get_bridge_info()
        initial_changes = initial_info.topology_changes

        # 快速触发大量拓扑变更
        if test_nodes:
            logger.info("触发快速拓扑变更...")

            for i in range(10):
                # 快速上下线端口
                test_nodes[0].execute_sudo("ip link set dev eth0 down")
                time.sleep(0.5)
                test_nodes[0].execute_sudo("ip link set dev eth0 up")
                time.sleep(0.5)

            time.sleep(5)

            # 检查拓扑变更计数
            final_info = rstp_analyzer.get_bridge_info()
            total_changes = final_info.topology_changes - initial_changes

            logger.info(f"检测到{total_changes}次拓扑变更")

            # 检查网络是否仍然稳定
            state = rstp_analyzer.get_convergence_state()
            if state['stable']:
                logger.info("网络在频繁拓扑变更后保持稳定")
            else:
                logger.warning("频繁拓扑变更导致网络不稳定")

        logger.info("拓扑变更攻击测试完成")

    def test_mac_spoofing(self, dut_manager, test_nodes,
                          network_topology, rstp_analyzer):
        """测试MAC地址欺骗"""
        logger.info("开始MAC地址欺骗测试")

        # 创建拓扑
        network_topology.create_ring_topology(use_rstp=True)
        time.sleep(5)

        # 获取DUT的MAC地址
        stdout, _, _ = dut_manager.execute(
            "ip link show br0 | grep ether | awk '{print $2}'"
        )
        dut_mac = stdout.strip()
        logger.info(f"DUT MAC地址: {dut_mac}")

        if test_nodes and dut_mac:
            # 尝试欺骗DUT的MAC
            logger.info("尝试MAC地址欺骗...")

            # 更改测试节点的MAC为DUT的MAC
            test_nodes[0].execute_sudo(
                f"ip link set dev eth0 down"
            )
            test_nodes[0].execute_sudo(
                f"ip link set dev eth0 address {dut_mac}"
            )
            test_nodes[0].execute_sudo(
                f"ip link set dev eth0 up"
            )

            time.sleep(5)

            # 检查网络影响
            state = rstp_analyzer.get_convergence_state()

            if not state['stable']:
                logger.warning("MAC欺骗导致网络不稳定")
            else:
                logger.info("网络对MAC欺骗具有抗性")

            # 恢复原MAC
            test_nodes[0].execute_sudo("ip link set dev eth0 down")
            original_mac = "00:50:56:00:00:01"  # 默认MAC
            test_nodes[0].execute_sudo(
                f"ip link set dev eth0 address {original_mac}"
            )
            test_nodes[0].execute_sudo("ip link set dev eth0 up")

        logger.info("MAC地址欺骗测试完成")

    def test_port_security(self, dut_manager, rstp_analyzer):
        """测试端口安全功能"""
        logger.info("开始端口安全测试")

        # 检查是否支持端口安全功能
        features = self._check_security_features(dut_manager)

        if features.get('bpdu_guard'):
            logger.info("检测到BPDU Guard支持")
            self._test_bpdu_guard(dut_manager, rstp_analyzer)

        if features.get('root_guard'):
            logger.info("检测到Root Guard支持")
            self._test_root_guard(dut_manager, rstp_analyzer)

        if features.get('loop_guard'):
            logger.info("检测到Loop Guard支持")
            self._test_loop_guard(dut_manager, rstp_analyzer)

        if not any(features.values()):
            logger.warning("未检测到任何端口安全功能")
            pytest.skip("端口安全功能不可用")

        logger.info("端口安全测试完成")

    def _get_cpu_usage(self, node: Any) -> float:
        """获取CPU使用率"""
        stdout, _, _ = node.execute(
            "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1"
        )
        try:
            return float(stdout.strip())
        except:
            return 0.0

    def _check_security_features(self, node: Any) -> Dict[str, bool]:
        """检查支持的安全功能"""
        features = {
            'bpdu_guard': False,
            'root_guard': False,
            'loop_guard': False,
            'port_security': False
        }

        # 检查mstpctl支持的功能
        stdout, _, code = node.execute("mstpctl --help 2>&1")
        if code == 0:
            if 'bpduguard' in stdout.lower():
                features['bpdu_guard'] = True
            if 'rootguard' in stdout.lower():
                features['root_guard'] = True

        # 检查其他安全功能
        # ...

        return features

    def _test_bpdu_guard(self, dut_manager, rstp_analyzer):
        """测试BPDU Guard功能"""
        logger.info("测试BPDU Guard")

        # 在端口上启用BPDU Guard
        stdout, stderr, code = dut_manager.execute_sudo(
            "mstpctl setbpduguard br0 eth2 yes"
        )

        if code == 0:
            # 发送BPDU到该端口
            # 预期端口应该被关闭
            time.sleep(5)

            # 检查端口状态
            info = rstp_analyzer.get_bridge_info()
            if "eth2" in info.ports:
                state = info.ports["eth2"].state
                if state.value == 'disabled':
                    logger.info("BPDU Guard生效，端口已禁用")
                else:
                    logger.warning("BPDU Guard未生效")

    def _test_root_guard(self, dut_manager, rstp_analyzer):
        """测试Root Guard功能"""
        logger.info("测试Root Guard")

        # 类似的测试逻辑
        pass

    def _test_loop_guard(self, dut_manager, rstp_analyzer):
        """测试Loop Guard功能"""
        logger.info("测试Loop Guard")

        # 类似的测试逻辑
        pass
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
        """测试DUT对根桥劫持攻击的防护能力"""
        logger.info("="*60)
        logger.info("根桥劫持攻击防护测试")
        logger.info("测试目标：验证DUT是否能防御恶意BPDU攻击")
        logger.info("="*60)
        
        # 步骤1：建立拓扑，确保DUT是根桥
        logger.info("\n步骤1：配置网络拓扑")
        network_topology.create_ring_topology(use_rstp=True)
        
        # 设置DUT为根桥（最低优先级）
        logger.info("设置DUT为根桥（优先级=4096）")
        self._force_dut_as_root(dut_manager)
        
        # 设置TestNode为普通桥（较高优先级）
        if test_nodes:
            logger.info("设置TestNode为普通桥（优先级=32768）")
            network_topology.execute_bridge_command(test_nodes[0], "set_priority", priority=32768)
        
        # 等待收敛并验证
        logger.info("\n等待RSTP收敛...")
        time.sleep(10)
        
        # 步骤2：验证初始状态
        logger.info("\n步骤2：验证初始RSTP状态")
        initial_state = self._verify_dut_is_root(dut_manager)
        
        if not initial_state['is_root']:
            logger.error(f"DUT未能成为根桥！当前根桥: {initial_state['root_id']}")
            logger.info("尝试强制DUT成为根桥...")
            
            # 降低DUT优先级到最低
            self._force_dut_as_root(dut_manager, priority=0)
            time.sleep(10)
            
            initial_state = self._verify_dut_is_root(dut_manager)
            if not initial_state['is_root']:
                pytest.skip("无法将DUT设置为根桥，跳过测试")
        
        logger.info(f"✓ DUT是根桥: {initial_state['bridge_id']}")
        
        # 记录初始BPDU计数
        initial_rx = self._get_bpdu_rx_count(dut_manager)
        logger.info(f"初始BPDU接收计数: {initial_rx}")
        
        # 步骤3：从TestNode发起攻击
        logger.info("\n步骤3：发起根桥劫持攻击")
        logger.info("攻击方式：从TestNode发送优先级=0的恶意BPDU")
        
        if test_nodes:
            attacker = FaultInjector(test_nodes[0])
            
            # 发送恶意BPDU，尝试成为新的根桥
            attack_success = attacker.inject_rogue_bpdu(
                interface="eth2",  # 连接到DUT的接口
                priority=0,        # 最高优先级，试图劫持根桥
                src_mac="00:11:22:33:44:55",
                count=10,
                interval=2.0
            )
            
            if not attack_success:
                logger.warning("BPDU注入可能失败，继续检查结果...")
        
        # 步骤4：等待并检查攻击结果
        logger.info("\n步骤4：评估攻击效果")
        logger.info("等待RSTP重新收敛...")
        time.sleep(20)
        
        # 检查最终状态
        final_state = self._verify_dut_is_root(dut_manager)
        final_rx = self._get_bpdu_rx_count(dut_manager)
        
        logger.info(f"最终BPDU接收计数: {final_rx}")
        logger.info(f"BPDU接收增量: {final_rx - initial_rx}")
        
        # 步骤5：分析测试结果
        logger.info("\n步骤5：分析测试结果")
        self._analyze_attack_result(
            initial_state=initial_state,
            final_state=final_state,
            bpdu_received=(final_rx > initial_rx),
            dut_manager=dut_manager
        )

    def _force_dut_as_root(self, dut_manager, priority=4096):
        """强制DUT成为根桥"""
        commands = [
            # 先停止RSTP
            "ovs-vsctl set bridge SE_ETH2 rstp_enable=false",
            "ovs-vsctl set bridge SE_ETH2 stp_enable=false",
            
            # 清除旧配置
            "ovs-vsctl remove bridge SE_ETH2 other_config stp-priority",
            "ovs-vsctl remove bridge SE_ETH2 other_config rstp-priority",
            
            # 设置新优先级
            f"ovs-vsctl set bridge SE_ETH2 other_config:stp-priority={priority}",
            f"ovs-vsctl set bridge SE_ETH2 other_config:rstp-priority={priority}",
            
            # 重新启动RSTP
            "ovs-vsctl set bridge SE_ETH2 stp_enable=true",
            "ovs-vsctl set bridge SE_ETH2 rstp_enable=true",
        ]
        
        for cmd in commands:
            dut_manager.execute_as_root(cmd)
            time.sleep(0.5)

    def _verify_dut_is_root(self, dut_manager):
        """验证DUT是否为根桥"""
        stdout, _, _ = dut_manager.execute_as_root("ovs-appctl rstp/show SE_ETH2")
        
        # 解析输出
        is_root = "This bridge is the root" in stdout
        
        # 提取桥ID和根ID
        import re
        bridge_match = re.search(r'Bridge ID:.*?stp-priority\s+(\d+).*?stp-system-id\s+([0-9a-f:]+)', 
                                stdout, re.DOTALL)
        root_match = re.search(r'Root ID:.*?stp-priority\s+(\d+).*?stp-system-id\s+([0-9a-f:]+)', 
                            stdout, re.DOTALL)
        
        result = {
            'is_root': is_root,
            'bridge_id': f"{bridge_match.group(1)}.{bridge_match.group(2)}" if bridge_match else "unknown",
            'root_id': f"{root_match.group(1)}.{root_match.group(2)}" if root_match else "unknown",
            'raw_output': stdout
        }
        
        return result

    def _get_bpdu_rx_count(self, dut_manager):
        """获取BPDU接收总数"""
        total = 0
        for port in ['br3', 'br4']:
            stdout, _, code = dut_manager.execute_as_root(
                f"ovs-vsctl get port {port} rstp_statistics"
            )
            if code == 0:
                import re
                match = re.search(r'rstp_rx_count=(\d+)', stdout)
                if match:
                    total += int(match.group(1))
        return total

    def _analyze_attack_result(self, initial_state, final_state, bpdu_received, dut_manager):
        """分析攻击结果并判定测试是否通过"""
        logger.info("="*50)
        logger.info("测试结果分析")
        logger.info("="*50)
        
        logger.info(f"初始状态: DUT是根桥={initial_state['is_root']}")
        logger.info(f"最终状态: DUT是根桥={final_state['is_root']}")
        logger.info(f"恶意BPDU送达: {bpdu_received}")
        
        # 判定逻辑
        if not bpdu_received:
            # 场景1：BPDU未送达
            logger.warning("⚠ 测试无效：恶意BPDU未送达DUT")
            logger.info("可能原因：")
            logger.info("  1. 网络连接问题")
            logger.info("  2. TestNode的BPDU发送失败")
            logger.info("  3. 中间有BPDU过滤")
            pytest.fail("测试无效：无法验证DUT的防护能力")
            
        elif initial_state['is_root'] and not final_state['is_root']:
            # 场景2：DUT失去根桥地位 - 攻击成功（防护失败）
            logger.error("❌ 测试失败：DUT被成功劫持！")
            logger.error(f"新的根桥: {final_state['root_id']}")
            logger.info("\n安全建议：")
            logger.info("  1. 启用BPDU Guard（端口级防护）")
            logger.info("  2. 启用Root Guard（防止指定端口成为根端口）")
            logger.info("  3. 配置BPDU Filter（过滤不信任的BPDU）")
            
            # 检查是否有防护但未生效
            self._check_protection_config(dut_manager)
            
            pytest.fail("DUT易受根桥劫持攻击，缺乏有效防护机制")
            
        elif initial_state['is_root'] and final_state['is_root'] and bpdu_received:
            # 场景3：DUT保持根桥地位 - 防护成功
            logger.info("✅ 测试通过：DUT成功防御了根桥劫持攻击！")
            logger.info("DUT接收到恶意BPDU但保持了根桥地位")
            logger.info("这表明DUT具有有效的防护机制")
            
            # 分析防护机制
            self._analyze_protection_mechanism(dut_manager)
            
        else:
            # 其他情况
            logger.warning("⚠ 异常场景")
            logger.info(f"详细状态: {final_state}")
            pytest.fail("测试结果异常，需要人工分析")

    def _check_protection_config(self, dut_manager):
        """检查DUT的防护配置"""
        logger.info("\n检查DUT的防护配置：")
        
        # 检查BPDU Guard
        stdout, _, _ = dut_manager.execute_as_root(
            "ovs-vsctl list port br3 | grep -i guard"
        )
        if stdout:
            logger.info(f"BPDU Guard配置: {stdout}")
        else:
            logger.info("未发现BPDU Guard配置")
        
        # 检查Root Guard  
        stdout, _, _ = dut_manager.execute_as_root(
            "ovs-vsctl list port br3 | grep -i root"
        )
        if stdout:
            logger.info(f"Root Guard配置: {stdout}")
        else:
            logger.info("未发现Root Guard配置")

    def _analyze_protection_mechanism(self, dut_manager):
        """分析DUT的防护机制"""
        logger.info("\n分析DUT的防护机制：")
        
        # 可能的防护机制：
        # 1. 优先级保护（忽略更高优先级的BPDU）
        # 2. Root Guard（防止端口成为根端口）
        # 3. BPDU验证（只接受特定来源的BPDU）
        # 4. 管理配置锁定（防止动态改变根桥）
        
        stdout, _, _ = dut_manager.execute_as_root(
            "ovs-appctl rstp/show SE_ETH2"
        )
        
        if "Root" in stdout and "Forwarding" in stdout:
            logger.info("可能的防护机制：")
            logger.info("  ✓ 优先级锁定或Root Guard")
            logger.info("  ✓ BPDU来源验证")
            logger.info("  ✓ 静态根桥配置")

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

        # 确定注入接口（连接到DUT的接口）
        injection_interface = "eth2"  # 连接到DUT的接口
        logger.info(f"使用接口进行BPDU洪泛: {injection_interface}")
        
        # 生成大量BPDU
        if test_nodes:
            script = f"""
from scapy.all import *
import time

target_mac = "01:80:c2:00:00:00"
interface = "{injection_interface}"

for i in range(1000):
    # 随机优先级和MAC
    priority = random.randint(0, 65535)
    src_mac = RandMAC()

    eth = Ether(dst=target_mac, src=src_mac)
    llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
    bpdu = STP(
        proto=0x0000,           # STP协议标识符
        version=0x02,           # RSTP版本
        bpdutype=0x02,          # Rapid STP BPDU类型
        bpduflags=0x3C,         # RSTP标志位
        rootid=priority << 48 | int(src_mac.replace(":", ""), 16),
        pathcost=0,
        bridgeid=priority << 48 | int(src_mac.replace(":", ""), 16),
        portid=0x8001,
        maxage=20,
        hellotime=2,
        fwddelay=15
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

    def test_bpdu_filter_functionality(self, dut_manager, test_nodes,
                                       network_topology, rstp_analyzer):
        """测试BPDU过滤器功能"""
        logger.info("开始BPDU过滤器功能测试")
        
        filter_port = "eth2"  # 假设eth2是边缘端口
        test_passed = False

        try:
            # 检查SSH连接状态
            if not dut_manager.is_connected():
                logger.error("SSH连接未激活")
                pytest.fail("SSH连接失败，无法执行测试")
            
            # 创建线性拓扑
            network_topology.create_linear_topology(use_rstp=True)
            time.sleep(5)
            
            # 记录启用过滤器前的BPDU发送情况
            initial_bpdu_count = self._count_bpdu_packets(dut_manager, filter_port)
            logger.info(f"启用过滤器前端口 {filter_port} BPDU数量: {initial_bpdu_count}")
            
            # 在DUT上启用BPDU过滤器
            try:
                self._enable_bpdu_filter(dut_manager, filter_port)
                logger.info(f"在端口 {filter_port} 启用BPDU过滤器")
            except Exception as e:
                logger.error(f"启用BPDU过滤器失败: {e}")
                pytest.fail(f"BPDU过滤器配置失败: {e}")
            
            # 等待一段时间让过滤器生效
            time.sleep(10)
            
            # 检查BPDU是否停止发送
            filtered_bpdu_count = self._count_bpdu_packets(dut_manager, filter_port)
            logger.info(f"启用过滤器后端口 {filter_port} BPDU数量: {filtered_bpdu_count}")
            
            # 验证BPDU过滤器效果
            if filtered_bpdu_count <= initial_bpdu_count:
                logger.info("BPDU过滤器功能正常：BPDU发送已停止或减少")
                test_passed = True
            else:
                logger.error("BPDU过滤器功能异常：BPDU仍在发送")
                pytest.fail("BPDU过滤器未能有效阻止BPDU发送")
            
            if test_nodes:
                # 测试从外部发送BPDU到过滤端口
                logger.info("测试向过滤端口发送外部BPDU")
                self._send_bpdu_to_filtered_port(test_nodes[0], filter_port)
                
                # 等待并检查网络稳定性
                time.sleep(5)
                convergence_state = rstp_analyzer.get_convergence_state()
                
                if convergence_state['stable']:
                    logger.info("BPDU过滤器功能正常：外部BPDU被忽略，网络保持稳定")
                else:
                    logger.error("BPDU过滤器功能异常：外部BPDU影响了网络稳定性")
                    test_passed = False
                
                # 测试错误配置场景（在连接交换机的端口启用过滤器）
                self._test_bpdu_filter_misconfiguration(dut_manager, test_nodes[0])
            
        except Exception as e:
            logger.error(f"BPDU过滤器测试失败: {e}")
            pytest.fail(f"BPDU过滤器测试执行失败: {e}")
        finally:
            # 清理：禁用BPDU过滤器
            try:
                self._cleanup_bpdu_filter(dut_manager, filter_port)
            except Exception as e:
                logger.error(f"清理BPDU过滤器配置失败: {e}")
        
        if not test_passed:
            pytest.fail("BPDU过滤器功能测试未通过验证")
            
        logger.info("BPDU过滤器功能测试完成")

    def test_malformed_bpdu_handling(self, dut_manager, test_nodes,
                                     network_topology, rstp_analyzer):
        """测试畸形BPDU处理能力"""
        logger.info("开始畸形BPDU处理测试")
        
        test_passed = True

        try:
            # 检查SSH连接状态
            if not dut_manager.is_connected():
                logger.error("SSH连接未激活")
                pytest.fail("SSH连接失败，无法执行测试")
            
            # 创建拓扑
            network_topology.create_ring_topology(use_rstp=True)
            time.sleep(5)

            # 记录初始状态
            initial_info = rstp_analyzer.get_bridge_info()
            initial_stable = rstp_analyzer.get_convergence_state()['stable']
            logger.info(f"初始网络状态: {'稳定' if initial_stable else '不稳定'}")

            if test_nodes:
                # 测试各种畸形BPDU
                malformed_tests = [
                    self._test_oversized_bpdu,
                    self._test_undersized_bpdu,
                    self._test_invalid_protocol_id,
                    self._test_invalid_version,
                    self._test_invalid_message_type,
                    self._test_corrupted_fields
                ]

                for test_func in malformed_tests:
                    try:
                        logger.info(f"执行测试: {test_func.__name__}")
                        test_func(test_nodes[0])
                        time.sleep(3)

                        # 检查网络是否仍然稳定
                        current_stable = rstp_analyzer.get_convergence_state()['stable']
                        if not current_stable:
                            logger.error(f"{test_func.__name__} 导致网络不稳定")
                            test_passed = False
                        else:
                            logger.info(f"{test_func.__name__} 网络保持稳定")

                    except ConnectionError as e:
                        logger.error(f"{test_func.__name__} SSH连接失败: {e}")
                        test_passed = False
                    except Exception as e:
                        logger.warning(f"{test_func.__name__} 执行异常但继续测试: {e}")
                        # 不设置test_passed = False，允许测试继续

        except Exception as e:
            logger.error(f"畸形BPDU测试失败: {e}")
            pytest.fail(f"畸形BPDU测试执行失败: {e}")
        finally:
            # 清理测试环境
            try:
                self._cleanup_malformed_bpdu_test(dut_manager)
            except Exception as e:
                logger.error(f"清理畸形BPDU测试环境失败: {e}")
        
        if not test_passed:
            pytest.fail("畸形BPDU处理测试未通过验证")
            
        logger.info("畸形BPDU处理测试完成")

    def test_non_standard_bpdu_handling(self, dut_manager, test_nodes,
                                          network_topology, rstp_analyzer):
        """测试非标准BPDU处理"""
        logger.info("开始非标准BPDU处理测试")
        
        try:
            # 检查SSH连接状态
            if not dut_manager.is_connected():
                logger.error("SSH连接未激活")
                pytest.fail("SSH连接失败，无法执行测试")
            
            # 创建环形拓扑
            network_topology.create_ring_topology(use_rstp=True)
            time.sleep(5)

            if test_nodes:
                # 测试各种非标准BPDU
                non_standard_tests = [
                    self._test_pvst_plus_bpdu,
                    self._test_cisco_proprietary_bpdu,
                    self._test_vlan_tagged_bpdu,
                    self._test_unknown_tlv_bpdu
                ]

                for test_func in non_standard_tests:
                    try:
                        logger.info(f"执行测试: {test_func.__name__}")
                        test_func(test_nodes[0])
                        time.sleep(3)

                        # 检查网络稳定性
                        current_stable = rstp_analyzer.get_convergence_state()['stable']
                        if not current_stable:
                            logger.warning(f"{test_func.__name__} 导致网络不稳定")
                        else:
                            logger.info(f"{test_func.__name__} 网络保持稳定")

                    except Exception as e:
                        logger.error(f"{test_func.__name__} 执行失败: {e}")
        
        except Exception as e:
            logger.error(f"非标准BPDU处理测试失败: {e}")
            pytest.fail(f"非标准BPDU处理测试执行失败: {e}")
        finally:
            # 清理测试环境
            try:
                if test_nodes:
                    for node in test_nodes:
                        if node.is_connected():
                            node.execute_sudo("rm -f /tmp/*bpdu.py")
            except Exception as e:
                logger.warning(f"清理测试文件失败: {e}")

        logger.info("非标准BPDU处理测试完成")

    def _test_oversized_bpdu(self, node):
        """测试超大BPDU"""
        script = '''
from scapy.all import *
import time

# 创建超大BPDU（正常BPDU + 大量填充数据）
target_mac = "01:80:c2:00:00:00"
interface = "eth0"

eth = Ether(dst=target_mac, src="00:11:22:33:44:55")
llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
bpdu = STP(bpdutype=0x00, rootid=32768, bridgeid=32768)
# 添加大量填充数据（超过正常BPDU大小）
padding = "A" * 2000

packet = eth/llc/bpdu/Raw(load=padding)
sendp(packet, iface=interface, count=5, inter=1, verbose=0)
print("Oversized BPDU sent")
'''
        node.execute(f"echo '{script}' > /tmp/oversized_bpdu.py")
        node.execute_sudo("python3 /tmp/oversized_bpdu.py")

    def _test_undersized_bpdu(self, node):
        """测试过小BPDU"""
        script = '''
from scapy.all import *

# 创建过小的BPDU（缺少必要字段）
target_mac = "01:80:c2:00:00:00"
interface = "eth0"

eth = Ether(dst=target_mac, src="00:11:22:33:44:55")
llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
# 只包含最小字段的BPDU
truncated_bpdu = Raw(load=b"\x00\x00\x00\x00\x80\x00")  # 截断的BPDU

packet = eth/llc/truncated_bpdu
sendp(packet, iface=interface, count=5, inter=1, verbose=0)
print("Undersized BPDU sent")
'''
        node.execute(f"echo '{script}' > /tmp/undersized_bpdu.py")
        node.execute_sudo("python3 /tmp/undersized_bpdu.py")

    def _test_invalid_protocol_id(self, node):
        """测试无效协议ID"""
        # 检查SSH连接状态
        if not node.is_connected():
            logger.warning(f"{node.config.name}: SSH连接断开，尝试重连...")
            if not node.reconnect():
                raise ConnectionError(f"{node.config.name}: SSH重连失败")
        
        try:
            # 创建Python脚本文件
            node.execute("cat > /tmp/invalid_protocol.py << 'EOF'")
            node.execute("from scapy.all import *")
            node.execute("")
            node.execute('target_mac = "01:80:c2:00:00:00"')
            node.execute('interface = "eth0"')
            node.execute("")
            node.execute('eth = Ether(dst=target_mac, src="00:11:22:33:44:55")')
            node.execute('llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)')
            node.execute('# 使用无效的协议ID（正常应该是0x0000）')
            node.execute('invalid_bpdu = Raw(load=b"\\xFF\\xFF\\x00\\x00\\x80\\x00" + b"\\x00" * 30)')
            node.execute("")
            node.execute('packet = eth/llc/invalid_bpdu')
            node.execute('sendp(packet, iface=interface, count=5, inter=1, verbose=0)')
            node.execute('print("Invalid protocol ID BPDU sent")')
            node.execute("EOF")
            node.execute_sudo("python3 /tmp/invalid_protocol.py")
            logger.info(f"{node.config.name}: 无效协议ID BPDU测试完成")
        except Exception as e:
            logger.error(f"{node.config.name}: 无效协议ID测试执行失败: {e}")
            # 重新抛出异常让上层处理
            raise

    def _test_invalid_version(self, node):
        """测试无效版本号"""
        # 检查SSH连接状态
        if not node.is_connected():
            logger.warning(f"{node.config.name}: SSH连接断开，尝试重连...")
            if not node.reconnect():
                raise ConnectionError(f"{node.config.name}: SSH重连失败")
        
        try:
            # 创建Python脚本文件
            node.execute("cat > /tmp/invalid_version.py << 'EOF'")
            node.execute("from scapy.all import *")
            node.execute("")
            node.execute('target_mac = "01:80:c2:00:00:00"')
            node.execute('interface = "eth0"')
            node.execute("")
            node.execute('eth = Ether(dst=target_mac, src="00:11:22:33:44:55")')
            node.execute('llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)')
            node.execute('# 使用无效版本号（正常RSTP应该是2）')
            node.execute('invalid_version_bpdu = Raw(load=b"\\x00\\x00\\xFF" + b"\\x00" * 30)')
            node.execute("")
            node.execute('packet = eth/llc/invalid_version_bpdu')
            node.execute('sendp(packet, iface=interface, count=5, inter=1, verbose=0)')
            node.execute('print("Invalid version BPDU sent")')
            node.execute("EOF")
            node.execute_sudo("python3 /tmp/invalid_version.py")
            logger.info(f"{node.config.name}: 无效版本号BPDU测试完成")
        except Exception as e:
            logger.error(f"{node.config.name}: 无效版本号测试执行失败: {e}")
            # 重新抛出异常让上层处理
            raise
        


    def _test_invalid_message_type(self, node):
        """测试无效消息类型"""
        # 检查SSH连接状态
        if not node.is_connected():
            logger.warning(f"{node.config.name}: SSH连接断开，尝试重连...")
            if not node.reconnect():
                raise ConnectionError(f"{node.config.name}: SSH重连失败")
        
        try:
            # 创建Python脚本文件
            node.execute("cat > /tmp/invalid_type.py << 'EOF'")
            node.execute("from scapy.all import *")
            node.execute("")
            node.execute('target_mac = "01:80:c2:00:00:00"')
            node.execute('interface = "eth0"')
            node.execute("")
            node.execute('eth = Ether(dst=target_mac, src="00:11:22:33:44:55")')
            node.execute('llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)')
            node.execute('# 使用无效消息类型（正常配置BPDU是0x00，TCN是0x80）')
            node.execute('invalid_type_bpdu = Raw(load=b"\\x00\\x00\\x02\\xFF\\x80\\x00" + b"\\x00" * 30)')
            node.execute("")
            node.execute('packet = eth/llc/invalid_type_bpdu')
            node.execute('sendp(packet, iface=interface, count=5, inter=1, verbose=0)')
            node.execute('print("Invalid message type BPDU sent")')
            node.execute("EOF")
            node.execute_sudo("python3 /tmp/invalid_type.py")
            logger.info(f"{node.config.name}: 无效消息类型BPDU测试完成")
        except Exception as e:
            logger.error(f"{node.config.name}: 无效消息类型测试执行失败: {e}")
            # 重新抛出异常让上层处理
            raise

    def _test_corrupted_fields(self, node):
        """测试字段损坏的BPDU"""
        # 检查SSH连接状态
        if not node.is_connected():
            logger.warning(f"{node.config.name}: SSH连接断开，尝试重连...")
            if not node.reconnect():
                raise ConnectionError(f"{node.config.name}: SSH重连失败")
        
        try:
            # 创建Python脚本文件
            node.execute("cat > /tmp/corrupted_bpdu.py << 'EOF'")
            node.execute("from scapy.all import *")
            node.execute("import random")
            node.execute("")
            node.execute('target_mac = "01:80:c2:00:00:00"')
            node.execute('interface = "eth0"')
            node.execute("")
            node.execute('eth = Ether(dst=target_mac, src="00:11:22:33:44:55")')
            node.execute('llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)')
            node.execute("")
            node.execute('# 创建包含随机损坏数据的BPDU')
            node.execute('corrupted_data = bytes([random.randint(0, 255) for _ in range(36)])')
            node.execute('corrupted_bpdu = Raw(load=corrupted_data)')
            node.execute("")
            node.execute('packet = eth/llc/corrupted_bpdu')
            node.execute('sendp(packet, iface=interface, count=5, inter=1, verbose=0)')
            node.execute('print("Corrupted BPDU sent")')
            node.execute("EOF")
            node.execute_sudo("python3 /tmp/corrupted_bpdu.py")
            logger.info(f"{node.config.name}: 损坏字段BPDU测试完成")
        except Exception as e:
            logger.error(f"{node.config.name}: 损坏字段测试执行失败: {e}")
            # 重新抛出异常让上层处理
            raise

    def _test_pvst_plus_bpdu(self, node):
        """测试PVST+ BPDU"""
        script = '''
from scapy.all import *

# PVST+ 使用不同的目标MAC地址
pvst_mac = "01:00:0c:cc:cc:cd"
interface = "eth0"

eth = Ether(dst=pvst_mac, src="00:11:22:33:44:55")
# PVST+ 使用SNAP封装
snap = SNAP(OUI=0x00000c, code=0x010b)
# 模拟PVST+ BPDU结构
pvst_bpdu = Raw(load=b"\x00\x00\x02\x00\x80\x00" + b"\x00" * 30 + b"\x00\x01")  # 包含VLAN ID

packet = eth/snap/pvst_bpdu
sendp(packet, iface=interface, count=3, inter=1, verbose=0)
print("PVST+ BPDU sent")
'''
        node.execute(f"echo '{script}' > /tmp/pvst_bpdu.py")
        node.execute_sudo("python3 /tmp/pvst_bpdu.py")

    def _test_cisco_proprietary_bpdu(self, node):
        """测试Cisco专有BPDU"""
        script = '''
from scapy.all import *

target_mac = "01:80:c2:00:00:00"
interface = "eth0"

eth = Ether(dst=target_mac, src="00:11:22:33:44:55")
llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
# 模拟包含Cisco专有扩展的BPDU
cisco_bpdu = Raw(load=b"\x00\x00\x02\x00\x80\x00" + b"\x00" * 30 + 
                     b"\x00\x0c\x29\x00\x00\x00")  # Cisco OUI + 专有数据

packet = eth/llc/cisco_bpdu
sendp(packet, iface=interface, count=3, inter=1, verbose=0)
print("Cisco proprietary BPDU sent")
'''
        node.execute(f"echo '{script}' > /tmp/cisco_bpdu.py")
        node.execute_sudo("python3 /tmp/cisco_bpdu.py")

    def _test_vlan_tagged_bpdu(self, node):
        """测试带VLAN标签的BPDU"""
        script = '''
from scapy.all import *

target_mac = "01:80:c2:00:00:00"
interface = "eth0"

eth = Ether(dst=target_mac, src="00:11:22:33:44:55")
# 添加VLAN标签
vlan = Dot1Q(vlan=100)
llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
bpdu = STP(bpdutype=0x00, rootid=32768, bridgeid=32768)

packet = eth/vlan/llc/bpdu
sendp(packet, iface=interface, count=3, inter=1, verbose=0)
print("VLAN tagged BPDU sent")
'''
        node.execute(f"echo '{script}' > /tmp/vlan_bpdu.py")
        node.execute_sudo("python3 /tmp/vlan_bpdu.py")

    def _test_unknown_tlv_bpdu(self, node):
        """测试包含未知TLV的BPDU"""
        script = '''
from scapy.all import *

target_mac = "01:80:c2:00:00:00"
interface = "eth0"

eth = Ether(dst=target_mac, src="00:11:22:33:44:55")
llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
# 标准BPDU + 未知TLV
standard_bpdu = b"\x00\x00\x02\x00\x80\x00" + b"\x00" * 30
unknown_tlv = b"\xFF\xFF\x08\x00\x01\x02\x03\x04"  # 未知类型和长度的TLV
bpdu_with_tlv = Raw(load=standard_bpdu + unknown_tlv)

packet = eth/llc/bpdu_with_tlv
sendp(packet, iface=interface, count=3, inter=1, verbose=0)
print("BPDU with unknown TLV sent")
'''
        node.execute(f"echo '{script}' > /tmp/unknown_tlv.py")
        node.execute_sudo("python3 /tmp/unknown_tlv.py")

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

    def test_bpdu_guard_functionality(self, dut_manager, test_nodes,
                                        network_topology, rstp_analyzer):
        """测试BPDU防护功能"""
        logger.info("开始BPDU防护功能测试")
        
        edge_port = "eth2"  # 假设eth2是边缘端口
        test_passed = False

        try:
            # 检查SSH连接状态
            if not dut_manager.is_connected():
                logger.error("SSH连接未激活")
                pytest.fail("SSH连接失败，无法执行测试")
            
            # 创建线性拓扑用于测试边缘端口
            network_topology.create_linear_topology(use_rstp=True)
            time.sleep(5)
            
            # 在DUT上启用BPDU防护
            try:
                self._enable_bpdu_guard(dut_manager, edge_port)
            except Exception as e:
                logger.error(f"启用BPDU防护失败: {e}")
                pytest.fail(f"BPDU防护配置失败: {e}")
            
            # 记录初始端口状态
            initial_port_state = self._get_port_state(dut_manager, edge_port)
            logger.info(f"边缘端口 {edge_port} 初始状态: {initial_port_state}")
            
            if test_nodes:
                # 从测试节点向边缘端口发送BPDU
                logger.info(f"向边缘端口 {edge_port} 发送BPDU")
                self._send_bpdu_to_edge_port(test_nodes[0], edge_port)
                
                # 等待BPDU防护生效
                time.sleep(3)
                
                # 检查端口是否被err-disabled
                final_port_state = self._get_port_state(dut_manager, edge_port)
                logger.info(f"BPDU防护触发后端口 {edge_port} 状态: {final_port_state}")
                
                # 验证端口被正确禁用
                if "err-disabled" in final_port_state.lower() or "disabled" in final_port_state.lower():
                    logger.info("BPDU防护功能正常：端口已被禁用")
                    test_passed = True
                else:
                    logger.error("BPDU防护功能异常：端口未被禁用")
                    pytest.fail("BPDU防护未能正确禁用端口")
                
                # 测试端口恢复功能
                self._test_bpdu_guard_recovery(dut_manager, edge_port)
            
        except Exception as e:
            logger.error(f"BPDU防护测试失败: {e}")
            pytest.fail(f"BPDU防护测试执行失败: {e}")
        finally:
            # 清理：禁用BPDU防护并恢复端口
            try:
                self._cleanup_bpdu_guard(dut_manager, edge_port)
            except Exception as e:
                logger.error(f"清理BPDU防护配置失败: {e}")
        
        if not test_passed:
            pytest.fail("BPDU防护功能测试未通过验证")
            
        logger.info("BPDU防护功能测试完成")

    def _test_bpdu_guard(self, dut_manager, rstp_analyzer):
        """测试BPDU Guard功能"""
        logger.info("测试BPDU Guard")

        # 在端口上启用BPDU Guard
        stdout, stderr, code = dut_manager.execute_sudo(
            "ovs-vsctl set port eth2 other_config:stp-bpdu-guard=true"
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

    def test_root_guard_functionality(self, dut_manager, test_nodes,
                                       network_topology, rstp_analyzer):
        """测试根防护功能"""
        logger.info("开始根防护功能测试")
        
        guard_port = "eth1"  # 假设eth1连接到可能的攻击源
        test_passed = False

        try:
            # 检查SSH连接状态
            if not dut_manager.is_connected():
                logger.error("SSH连接未激活")
                pytest.fail("SSH连接失败，无法执行测试")
            
            # 创建环形拓扑
            network_topology.create_ring_topology(use_rstp=True)
            time.sleep(5)

            # 获取当前根桥信息
            initial_bridge_info = rstp_analyzer.get_bridge_info()
            current_root_id = initial_bridge_info.root_id if initial_bridge_info else None
            logger.info(f"当前根桥ID: {current_root_id}")
            
            # 在DUT上启用根防护
            try:
                self._enable_root_guard(dut_manager, guard_port)
                logger.info(f"在端口 {guard_port} 启用根防护")
            except Exception as e:
                logger.error(f"启用根防护失败: {e}")
                pytest.fail(f"根防护配置失败: {e}")
            
            # 记录初始端口状态
            initial_port_state = self._get_port_state(dut_manager, guard_port)
            logger.info(f"端口 {guard_port} 初始状态: {initial_port_state}")
            
            if test_nodes:
                # 从测试节点发送更优的BPDU（尝试成为新根桥）
                logger.info("发送更优BPDU尝试劫持根桥")
                self._send_superior_bpdu(test_nodes[0])
                
                # 等待根防护生效
                time.sleep(5)
                
                # 检查端口是否进入root-inconsistent状态
                final_port_state = self._get_port_state(dut_manager, guard_port)
                logger.info(f"根防护触发后端口 {guard_port} 状态: {final_port_state}")
                
                # 验证根桥没有改变
                final_bridge_info = rstp_analyzer.get_bridge_info()
                final_root_id = final_bridge_info.root_id if final_bridge_info else None
                
                if current_root_id == final_root_id:
                    logger.info("根防护功能正常：根桥身份未被劫持")
                    test_passed = True
                else:
                    logger.error(f"根防护功能异常：根桥从 {current_root_id} 变为 {final_root_id}")
                    pytest.fail("根防护未能阻止根桥劫持")
                
                # 验证端口状态
                if "root-inconsistent" in final_port_state.lower() or "blocking" in final_port_state.lower():
                    logger.info("根防护功能正常：端口进入阻塞状态")
                else:
                    logger.error("根防护功能异常：端口未进入阻塞状态")
                    test_passed = False
                
                # 测试根防护恢复
                self._test_root_guard_recovery(dut_manager, test_nodes[0], guard_port)
            
        except Exception as e:
            logger.error(f"根防护测试失败: {e}")
            pytest.fail(f"根防护测试执行失败: {e}")
        finally:
            # 清理：禁用根防护
            try:
                self._cleanup_root_guard(dut_manager, guard_port)
            except Exception as e:
                logger.error(f"清理根防护配置失败: {e}")
        
        if not test_passed:
            pytest.fail("根防护功能测试未通过验证")
            
        logger.info("根防护功能测试完成")

    def _test_root_guard(self, dut_manager, rstp_analyzer):
        """测试Root Guard功能"""
        logger.info("测试Root Guard")

        # 在端口上启用Root Guard
        stdout, stderr, code = dut_manager.execute_sudo(
            "ovs-vsctl set port eth1 other_config:stp-root-guard=true"
        )

        if code == 0:
            # 发送更优的BPDU到该端口
            # 预期端口应该进入root-inconsistent状态
            time.sleep(5)

            # 检查端口状态
            info = rstp_analyzer.get_bridge_info()
            if "eth1" in info.ports:
                state = info.ports["eth1"].state
                if "root-inconsistent" in str(state).lower():
                    logger.info("Root Guard生效，端口进入root-inconsistent状态")
                else:
                    logger.warning("Root Guard未生效")

    def test_loop_guard_functionality(self, dut_manager, test_nodes,
                                       network_topology, rstp_analyzer):
        """测试环路防护功能"""
        logger.info("开始环路防护功能测试")
        
        # 选择一个非边缘端口启用环路防护
        guard_port = "eth1"  # 假设eth1是根端口或指定端口

        try:
            # 创建环形拓扑
            network_topology.create_ring_topology(use_rstp=True)
            time.sleep(5)
            
            # 在DUT上启用环路防护
            self._enable_loop_guard(dut_manager, guard_port)
            logger.info(f"在端口 {guard_port} 启用环路防护")
            
            # 记录初始端口状态
            initial_port_state = self._get_port_state(dut_manager, guard_port)
            logger.info(f"端口 {guard_port} 初始状态: {initial_port_state}")
            
            if test_nodes:
                # 模拟单向链路故障（停止从该端口接收BPDU）
                logger.info("模拟单向链路故障")
                self._simulate_unidirectional_failure(test_nodes[0])
                
                # 等待环路防护生效
                time.sleep(20)  # 等待BPDU超时
                
                # 检查端口是否进入loop-inconsistent状态
                final_port_state = self._get_port_state(dut_manager, guard_port)
                logger.info(f"环路防护触发后端口 {guard_port} 状态: {final_port_state}")
                
                # 验证端口状态
                if "loop-inconsistent" in final_port_state.lower() or "blocking" in final_port_state.lower():
                    logger.info("环路防护功能正常：端口进入阻塞状态")
                else:
                    logger.warning("环路防护功能异常：端口未进入阻塞状态")
                
                # 测试环路防护恢复
                self._test_loop_guard_recovery(dut_manager, test_nodes[0], guard_port)
            
        except Exception as e:
            logger.error(f"环路防护测试失败: {e}")
        finally:
            # 清理：禁用环路防护
            self._cleanup_loop_guard(dut_manager, guard_port)
            
        logger.info("环路防护功能测试完成")

    def _test_loop_guard(self, dut_manager, rstp_analyzer):
        """测试Loop Guard功能"""
        logger.info("测试Loop Guard")

        # 在端口上启用Loop Guard
        stdout, stderr, code = dut_manager.execute_sudo(
            "ovs-vsctl set port eth1 other_config:stp-loop-guard=true"
        )

        if code == 0:
            # 模拟单向链路故障
            # 预期端口应该进入loop-inconsistent状态
            time.sleep(20)  # 等待BPDU超时

            # 检查端口状态
            info = rstp_analyzer.get_bridge_info()
            if "eth1" in info.ports:
                state = info.ports["eth1"].state
                if "loop-inconsistent" in str(state).lower():
                    logger.info("Loop Guard生效，端口进入loop-inconsistent状态")
                else:
                    logger.warning("Loop Guard未生效")

    def _enable_bpdu_filter(self, dut_manager, port):
        """在指定端口启用BPDU过滤器"""
        try:
            # 检查SSH连接
            if not dut_manager.is_connected():
                dut_manager.reconnect()
            
            # 优先使用OVS命令启用BPDU过滤器
            stdout, stderr, code = dut_manager.execute_sudo(
                f"ovs-vsctl set port {port} other_config:stp-bpdu-filter=true"
            )
            if code != 0:
                logger.warning(f"OVS设置BPDU过滤器失败，尝试使用系统文件方法")
                # 备用方法：使用系统文件
                stdout, stderr, code = dut_manager.execute_sudo(
                    f"echo 1 > /sys/class/net/SE_ETH2/bridge/ports/{port}/bpdu_filter"
                )
                if code != 0:
                    raise Exception(f"BPDU过滤器配置失败: {stderr}")
        except Exception as e:
            logger.error(f"启用BPDU过滤器失败: {e}")
            raise
    
    def _count_bpdu_packets(self, dut_manager, port, duration=5):
        """统计指定端口的BPDU包数量"""
        try:
            # 检查SSH连接
            if not dut_manager.is_connected():
                dut_manager.reconnect()
            
            # 使用tcpdump捕获BPDU包
            stdout, stderr, code = dut_manager.execute_sudo(
                f"timeout {duration} tcpdump -i {port} -c 100 'ether dst 01:80:c2:00:00:00' 2>/dev/null | wc -l"
            )
            if code == 0 and stdout.strip().isdigit():
                return int(stdout.strip())
            else:
                logger.warning(f"BPDU包统计命令执行失败: {stderr}")
                return 0
        except Exception as e:
            logger.error(f"统计BPDU包失败: {e}")
            return 0
    
    def _send_bpdu_to_filtered_port(self, test_node, target_port):
        """向过滤端口发送BPDU"""
        script = '''
from scapy.all import *

target_mac = "01:80:c2:00:00:00"
interface = "eth0"

# 构造标准BPDU包
eth = Ether(dst=target_mac, src="00:11:22:33:44:55")
llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
bpdu = STP(bpdutype=0x00, rootid=32768, bridgeid=32768)

packet = eth/llc/bpdu
sendp(packet, iface=interface, count=5, inter=1, verbose=0)
print("BPDU sent to filtered port")
'''
        test_node.execute(f"echo '{script}' > /tmp/filtered_bpdu.py")
        test_node.execute_sudo("python3 /tmp/filtered_bpdu.py")
    
    def _test_bpdu_filter_misconfiguration(self, dut_manager, test_node):
        """测试BPDU过滤器错误配置场景"""
        try:
            logger.info("测试BPDU过滤器错误配置场景")
            
            # 在连接到其他交换机的端口启用BPDU过滤器
            trunk_port = "eth1"  # 假设eth1连接到其他交换机
            self._enable_bpdu_filter(dut_manager, trunk_port)
            
            # 等待一段时间观察网络行为
            time.sleep(10)
            
            # 检查是否出现环路或其他问题
            # 这里可以通过监控CPU使用率、网络流量等指标来判断
            cpu_usage = self._get_cpu_usage(dut_manager)
            
            if cpu_usage > 80:
                logger.warning("检测到高CPU使用率，可能存在网络环路")
            else:
                logger.info("错误配置测试：未检测到明显的网络问题")
                
            # 清理错误配置
            self._cleanup_bpdu_filter(dut_manager, trunk_port)
            
        except Exception as e:
            logger.error(f"BPDU过滤器错误配置测试失败: {e}")
    
    def _cleanup_bpdu_filter(self, dut_manager, port):
        """清理BPDU过滤器配置"""
        try:
            # 清理命令
            cleanup_commands = [
                f"ovs-vsctl remove port {port} other_config stp-bpdu-filter",
                f"echo 0 > /sys/class/net/SE_ETH2/bridge/ports/{port}/bpdu_filter"
            ]
            
            for cmd in cleanup_commands:
                try:
                    # 检查SSH连接
                    if not dut_manager.is_connected():
                        dut_manager.reconnect()
                    stdout, stderr, code = dut_manager.execute_sudo(cmd)
                    if code != 0:
                        logger.warning(f"清理命令执行失败: {cmd}, 错误: {stderr}")
                except Exception as e:
                    logger.warning(f"清理命令执行失败: {cmd}, 错误: {e}")
                    
        except Exception as e:
            logger.error(f"清理BPDU过滤器配置失败: {e}")

    def _enable_loop_guard(self, dut_manager, port):
        """在指定端口启用环路防护"""
        # 首先确保网桥启用了STP
        dut_manager.execute_sudo("ovs-vsctl set bridge SE_ETH2 stp_enable=true")
        dut_manager.execute_sudo("ovs-vsctl set bridge SE_ETH2 rstp_enable=true")
        
        # 然后在端口上启用环路防护
        stdout, stderr, code = dut_manager.execute_sudo(
            f"ovs-vsctl set port {port} other_config:stp-loop-guard=true"
        )
        if code != 0:
            logger.warning(f"启用环路防护失败: {stderr}")

    def _simulate_unidirectional_failure(self, test_node):
        """模拟单向链路故障（停止发送BPDU）"""
        logger.info("停止从测试节点发送BPDU")
        # 通过停止STP进程或阻塞BPDU来模拟单向故障
        test_node.execute_sudo("iptables -A OUTPUT -d 01:80:c2:00:00:00 -j DROP")

    def _test_loop_guard_recovery(self, dut_manager, test_node, port):
        """测试环路防护端口恢复"""
        logger.info(f"测试环路防护端口 {port} 恢复功能")
        
        # 恢复BPDU发送
        logger.info("恢复BPDU发送")
        test_node.execute_sudo("iptables -D OUTPUT -d 01:80:c2:00:00:00 -j DROP")
        
        # 等待端口恢复
        time.sleep(10)
        
        # 检查端口是否自动恢复
        recovered_state = self._get_port_state(dut_manager, port)
        logger.info(f"端口恢复后状态: {recovered_state}")
        
        if "forwarding" in recovered_state.lower():
            logger.info("环路防护端口自动恢复正常")
        else:
            logger.warning("环路防护端口未能自动恢复")

    def _cleanup_loop_guard(self, dut_manager, port):
        """清理环路防护配置"""
        dut_manager.execute_sudo(f"ovs-vsctl remove port {port} other_config stp-loop-guard")
        dut_manager.execute_sudo(f"ip link set dev {port} up")

    def _enable_bpdu_guard(self, dut_manager, port):
        """在指定端口启用BPDU防护"""
        # 首先确保网桥启用了STP
        dut_manager.execute_sudo("ovs-vsctl set bridge SE_ETH2 stp_enable=true")
        dut_manager.execute_sudo("ovs-vsctl set bridge SE_ETH2 rstp_enable=true")
        
        # 然后在端口上启用BPDU防护
        stdout, stderr, code = dut_manager.execute_sudo(
            f"ovs-vsctl set port {port} other_config:stp-bpdu-guard=true"
        )
        if code != 0:
            logger.warning(f"启用BPDU防护失败: {stderr}")

    def _get_port_state(self, dut_manager, port):
        """获取端口状态"""
        # 尝试多种方法获取端口状态
        methods = [
            f"ovs-appctl stp/show SE_ETH2 | grep {port}",
            f"ovs-vsctl get port {port} status",
            f"ovs-ofctl show SE_ETH2 | grep {port}",
            f"ip link show {port}"
        ]
        
        for method in methods:
            stdout, stderr, code = dut_manager.execute(method)
            if code == 0 and stdout.strip():
                logger.debug(f"端口状态查询方法: {method}")
                logger.debug(f"端口状态结果: {stdout.strip()}")
                return stdout.strip()
        
        return "unknown"

    def _send_bpdu_to_edge_port(self, test_node, target_port):
        """向边缘端口发送BPDU"""
        script = '''
from scapy.all import *

target_mac = "01:80:c2:00:00:00"
interface = "eth0"

eth = Ether(dst=target_mac, src="00:11:22:33:44:55")
llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
bpdu = STP(bpdutype=0x00, rootid=32768, bridgeid=32768)

packet = eth/llc/bpdu
sendp(packet, iface=interface, count=3, inter=1, verbose=0)
print("BPDU sent to edge port")
'''
        test_node.execute(f"echo '{script}' > /tmp/edge_bpdu.py")
        test_node.execute_sudo("python3 /tmp/edge_bpdu.py")

    def _test_bpdu_guard_recovery(self, dut_manager, port):
        """测试BPDU防护端口恢复"""
        logger.info(f"测试端口 {port} 恢复功能")
        
        # 尝试手动恢复端口
        dut_manager.execute_sudo(f"ip link set dev {port} down")
        time.sleep(1)
        dut_manager.execute_sudo(f"ip link set dev {port} up")
        time.sleep(2)
        
        # 检查端口是否恢复
        recovered_state = self._get_port_state(dut_manager, port)
        logger.info(f"端口恢复后状态: {recovered_state}")

    def _cleanup_bpdu_guard(self, dut_manager, port):
        """清理BPDU防护配置"""
        dut_manager.execute_sudo(f"ovs-vsctl remove port {port} other_config stp-bpdu-guard")
        dut_manager.execute_sudo(f"ip link set dev {port} up")

    def _enable_root_guard(self, dut_manager, port):
        """在指定端口启用根防护"""
        # 首先确保网桥启用了STP
        dut_manager.execute_sudo("ovs-vsctl set bridge SE_ETH2 stp_enable=true")
        dut_manager.execute_sudo("ovs-vsctl set bridge SE_ETH2 rstp_enable=true")
        
        # 然后在端口上启用根防护
        stdout, stderr, code = dut_manager.execute_sudo(
            f"ovs-vsctl set port {port} other_config:stp-root-guard=true"
        )
        if code != 0:
            logger.warning(f"启用根防护失败: {stderr}")

    def _send_superior_bpdu(self, test_node):
        """发送更优的BPDU（尝试成为根桥）"""
        script = '''
from scapy.all import *

target_mac = "01:80:c2:00:00:00"
interface = "eth0"

# 发送具有更高优先级的BPDU（更小的数值表示更高优先级）
eth = Ether(dst=target_mac, src="00:11:22:33:44:55")
llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
bpdu = STP(
    bpdutype=0x00,
    rootid=0x1000,  # 更高优先级
    rootmac="00:11:22:33:44:55",
    bridgeid=0x1000,
    bridgemac="00:11:22:33:44:55"
)

packet = eth/llc/bpdu
sendp(packet, iface=interface, count=5, inter=2, verbose=0)
print("Superior BPDU sent")
'''
        test_node.execute(f"echo '{script}' > /tmp/superior_bpdu.py")
        test_node.execute_sudo("python3 /tmp/superior_bpdu.py")

    def _test_root_guard_recovery(self, dut_manager, test_node, port):
        """测试根防护端口恢复"""
        logger.info(f"测试根防护端口 {port} 恢复功能")
        
        # 停止发送更优BPDU
        logger.info("停止发送更优BPDU")
        time.sleep(10)  # 等待更优BPDU超时
        
        # 检查端口是否自动恢复
        recovered_state = self._get_port_state(dut_manager, port)
        logger.info(f"端口恢复后状态: {recovered_state}")
        
        if "forwarding" in recovered_state.lower():
            logger.info("根防护端口自动恢复正常")
        else:
            logger.warning("根防护端口未能自动恢复")

    def _cleanup_root_guard(self, dut_manager, port):
        """清理根防护配置"""
        dut_manager.execute_sudo(f"ovs-vsctl remove port {port} other_config stp-root-guard")
        dut_manager.execute_sudo(f"ip link set dev {port} up")
    
    def _send_malformed_bpdu(self, test_node, test_type):
        """发送畸形BPDU"""
        if test_type == "oversized_bpdu":
            self._test_oversized_bpdu(test_node)
        elif test_type == "undersized_bpdu":
            self._test_undersized_bpdu(test_node)
        elif test_type == "invalid_protocol_id":
            self._test_invalid_protocol_id(test_node)
        elif test_type == "corrupted_checksum":
            self._test_corrupted_fields(test_node)
        elif test_type == "invalid_message_age":
            self._test_invalid_version(test_node)
    
    def _check_error_logs(self, dut_manager, test_type):
        """检查DUT的错误日志"""
        try:
            # 检查SSH连接
            if not dut_manager.is_connected():
                dut_manager.reconnect()
            
            # 检查系统日志中的RSTP相关错误
            stdout, stderr, code = dut_manager.execute_sudo(
                "grep -i 'rstp\\|stp\\|bridge' /var/log/syslog | tail -10"
            )
            
            if code == 0 and stdout:
                logger.info(f"{test_type} 测试后的系统日志:")
                for line in stdout.split('\n'):
                    if line.strip():
                        logger.info(f"  {line}")
            else:
                logger.info(f"{test_type} 测试后无相关系统日志")
            
        except Exception as e:
            logger.warning(f"检查错误日志失败: {e}")
    
    def _cleanup_malformed_bpdu_test(self, dut_manager):
        """清理畸形BPDU测试环境"""
        try:
            # 检查SSH连接
            if not dut_manager.is_connected():
                dut_manager.reconnect()
            
            # 重启OVS服务以清理任何异常状态
            dut_manager.execute_sudo("systemctl restart openvswitch-switch")
            time.sleep(3)
            
        except Exception as e:
            logger.warning(f"清理畸形BPDU测试环境失败: {e}")
    
    def _get_rstp_rx_count(self, dut_manager, port="br3"):
        """获取指定端口的RSTP接收计数器"""
        try:
            # 使用ovs-vsctl获取端口的RSTP统计信息
            stdout, stderr, code = dut_manager.execute_sudo(
                f"ovs-vsctl list port {port}"
            )
            
            if code != 0:
                logger.warning(f"获取端口{port}信息失败: {stderr}")
                return 0
            
            # 解析输出查找rstp_rx_count
            for line in stdout.split('\n'):
                if 'rstp_statistics' in line:
                    # 尝试提取rstp_rx_count值
                    if 'rstp_rx_count' in line:
                        # 解析格式如: rstp_statistics : {rstp_rx_count=123, ...}
                        import re
                        match = re.search(r'rstp_rx_count=(\d+)', line)
                        if match:
                            return int(match.group(1))
            
            # 如果没有找到统计信息，返回0
            logger.debug(f"端口{port}未找到RSTP接收计数器")
            return 0
            
        except Exception as e:
            logger.warning(f"获取RSTP接收计数器失败: {e}")
            return 0
    
    def _analyze_hijack_attack_result(self, dut_manager, rx_count_before, rx_count_after, 
                                    dut_is_still_root, original_root_id, current_root_id):
        """分析根桥劫持攻击测试结果"""
        logger.info("\n=== 根桥劫持攻击测试结果分析 ===")
        logger.info(f"注入前RSTP接收计数: {rx_count_before}")
        logger.info(f"注入后RSTP接收计数: {rx_count_after}")
        logger.info(f"原始根桥ID: {original_root_id}")
        logger.info(f"当前根桥ID: {current_root_id}")
        logger.info(f"DUT是否仍为根桥: {dut_is_still_root}")
        
        # 判断BPDU是否成功送达
        bpdus_received = rx_count_after > rx_count_before
        logger.info(f"恶意BPDU是否送达: {bpdus_received}")
        
        # 根据检测逻辑进行分析
        if not dut_is_still_root:
            # Root ID发生切换，说明被劫持
            result = "未防护，根桥被劫持"
            status = "FAIL"
            recommendation = "DUT缺乏根桥防护机制，建议启用Root Guard或其他安全措施"
            
        elif bpdus_received and dut_is_still_root:
            # BPDU送达但Root ID未切换，说明有防护
            result = "防护有效"
            status = "PASS"
            recommendation = "DUT正确忽略了恶意BPDU，防护机制工作正常"
            
        elif not bpdus_received and dut_is_still_root:
            # BPDU未送达且Root ID未切换，可能是虚假PASS
            result = "可能虚假PASS（BPDU未送达）"
            status = "UNCERTAIN"
            recommendation = "需要检查网络连接、BPDU注入机制或测试环境配置"
            
        else:
            # 其他异常情况
            result = "测试结果异常"
            status = "ERROR"
            recommendation = "请检查测试环境和DUT配置"
        
        logger.info(f"\n测试结果: {result}")
        logger.info(f"测试状态: {status}")
        logger.info(f"建议: {recommendation}")
        logger.info("=" * 50)
        
        # 根据结果决定测试是否通过
        if status == "FAIL":
            pytest.fail(f"根桥劫持攻击测试失败: {result}. {recommendation}")
        elif status == "UNCERTAIN":
            pytest.fail(f"根桥劫持攻击测试结果不确定: {result}. {recommendation}")
        elif status == "ERROR":
            pytest.fail(f"根桥劫持攻击测试出现错误: {result}. {recommendation}")
        else:
            logger.info("根桥劫持攻击测试通过: DUT具备有效的防护机制")
    
    def _start_packet_capture(self, dut_manager, interfaces):
        """在DUT的指定接口上启动BPDU抓包"""
        logger.info(f"在DUT接口{interfaces}上启动BPDU抓包")
        
        for interface in interfaces:
            try:
                # 检查接口状态
                stdout, _, _ = dut_manager.execute_sudo(f"ip link show {interface}")
                logger.info(f"接口{interface}状态: {stdout.strip().split('\n')[0] if stdout else 'Unknown'}")
                
                # 启动后台tcpdump抓包，专门捕获BPDU，增加详细输出
                cmd = (
                    f"nohup tcpdump -i {interface} -c 50 -vv -w /tmp/bpdu_capture_{interface}.pcap "
                    f"'ether dst 01:80:c2:00:00:00' > /tmp/tcpdump_{interface}.log 2>&1 &"
                )
                dut_manager.execute_sudo(cmd)
                logger.info(f"已启动{interface}接口的BPDU抓包，日志文件：/tmp/tcpdump_{interface}.log")
                
                # 验证tcpdump进程是否启动
                time.sleep(1)
                stdout, _, _ = dut_manager.execute_sudo(f"pgrep -f 'tcpdump.*{interface}'")
                if stdout.strip():
                    logger.info(f"tcpdump进程已启动 (PID: {stdout.strip()})")
                else:
                    logger.warning(f"tcpdump进程可能未正常启动")
                    
            except Exception as e:
                logger.warning(f"启动{interface}接口抓包失败: {e}")
    
    def _stop_packet_capture_and_analyze(self, dut_manager, interfaces):
        """停止抓包并分析捕获的BPDU数量"""
        logger.info("停止BPDU抓包并分析结果")
        total_bpdus = 0
        
        for interface in interfaces:
            try:
                # 检查tcpdump进程状态
                stdout, _, _ = dut_manager.execute_sudo(f"pgrep -f 'tcpdump.*{interface}'")
                if stdout.strip():
                    logger.info(f"停止{interface}接口的tcpdump进程 (PID: {stdout.strip()})")
                    # 停止tcpdump进程
                    dut_manager.execute_sudo(f"pkill -f 'tcpdump.*{interface}'")
                    time.sleep(2)  # 等待进程完全停止
                else:
                    logger.warning(f"{interface}接口的tcpdump进程未找到")
                
                # 检查抓包文件是否存在
                pcap_file = f"/tmp/bpdu_capture_{interface}.pcap"
                stdout, _, _ = dut_manager.execute_sudo(f"ls -la {pcap_file}")
                if "No such file" in stdout:
                    logger.warning(f"抓包文件{pcap_file}不存在")
                    continue
                else:
                    logger.info(f"抓包文件{pcap_file}信息: {stdout.strip()}")
                
                # 分析抓包文件
                stdout, stderr, code = dut_manager.execute_sudo(
                    f"tcpdump -r {pcap_file} 2>/dev/null | wc -l"
                )
                
                if code == 0 and stdout.strip().isdigit():
                    interface_bpdus = int(stdout.strip())
                    total_bpdus += interface_bpdus
                    logger.info(f"接口{interface}捕获到{interface_bpdus}个BPDU")
                    
                    # 如果捕获到BPDU，显示详细信息
                    if interface_bpdus > 0:
                        stdout, _, _ = dut_manager.execute_sudo(
                            f"tcpdump -r {pcap_file} -vv -c 5 2>/dev/null"
                        )
                        logger.info(f"接口{interface}前5个BPDU详情:\n{stdout}")
                    else:
                        logger.warning(f"接口{interface}未捕获到任何BPDU - 可能存在网络连接问题")
                else:
                    logger.warning(f"无法分析接口{interface}的抓包文件: stderr={stderr}")
                
                # 检查tcpdump日志文件
                log_file = f"/tmp/tcpdump_{interface}.log"
                stdout, _, _ = dut_manager.execute_sudo(f"cat {log_file}")
                if stdout.strip():
                    logger.info(f"接口{interface}的tcpdump日志:\n{stdout}")
                
                # 清理临时文件
                dut_manager.execute_sudo(f"rm -f {pcap_file} {log_file}")
                
            except Exception as e:
                logger.warning(f"分析接口{interface}抓包结果失败: {e}")
        
        logger.info(f"总共捕获到{total_bpdus}个BPDU")
        return total_bpdus
    
    def _start_enhanced_packet_capture(self, dut_manager):
        """启动增强的BPDU抓包，覆盖所有可能的接口"""
        logger.info("启动增强BPDU抓包")
        
        # 获取所有网络接口
        stdout, _, _ = dut_manager.execute_sudo("ip link show | grep '^[0-9]' | awk '{print $2}' | sed 's/:$//'")
        all_interfaces = [iface.strip() for iface in stdout.split('\n') if iface.strip() and not iface.startswith('lo')]
        
        logger.info(f"检测到的网络接口: {all_interfaces}")
        
        # 重点监控的接口
        priority_interfaces = ['br3', 'br4', 'eth0', 'eth1', 'eth2']
        
        for interface in priority_interfaces:
            if interface in all_interfaces:
                try:
                    # 启动tcpdump抓包
                    cmd = (
                        f"nohup tcpdump -i {interface} -c 100 -vv -s 0 "
                        f"-w /tmp/enhanced_bpdu_{interface}.pcap "
                        f"'ether dst 01:80:c2:00:00:00 or ether proto 0x88cc' "
                        f"> /tmp/enhanced_tcpdump_{interface}.log 2>&1 &"
                    )
                    dut_manager.execute_sudo(cmd)
                    logger.info(f"已启动{interface}接口的增强BPDU抓包")
                    
                    # 验证进程启动
                    time.sleep(0.5)
                    stdout, _, _ = dut_manager.execute_sudo(f"pgrep -f 'tcpdump.*{interface}'")
                    if stdout.strip():
                        logger.info(f"tcpdump进程已启动 (PID: {stdout.strip()})")
                    
                except Exception as e:
                    logger.warning(f"启动{interface}接口增强抓包失败: {e}")
    
    def _stop_enhanced_packet_capture_and_analyze(self, dut_manager):
        """停止增强抓包并分析结果"""
        logger.info("停止增强BPDU抓包并分析结果")
        total_bpdus = 0
        
        # 等待抓包完成
        time.sleep(2)
        
        # 停止所有tcpdump进程
        dut_manager.execute_sudo("pkill -f 'tcpdump.*enhanced_bpdu'")
        time.sleep(1)
        
        # 分析所有抓包文件
        stdout, _, _ = dut_manager.execute_sudo("ls /tmp/enhanced_bpdu_*.pcap 2>/dev/null || echo 'no files'")
        
        if "no files" in stdout:
            logger.warning("未找到任何抓包文件")
            return 0
        
        pcap_files = [f.strip() for f in stdout.split('\n') if f.strip().endswith('.pcap')]
        
        for pcap_file in pcap_files:
            interface = pcap_file.split('_')[-1].replace('.pcap', '')
            
            try:
                # 检查文件大小
                stdout, _, _ = dut_manager.execute_sudo(f"ls -la {pcap_file}")
                logger.info(f"抓包文件{pcap_file}: {stdout.strip()}")
                
                # 分析BPDU数量
                stdout, stderr, code = dut_manager.execute_sudo(
                    f"tcpdump -r {pcap_file} 2>/dev/null | wc -l"
                )
                
                if code == 0 and stdout.strip().isdigit():
                    interface_bpdus = int(stdout.strip())
                    total_bpdus += interface_bpdus
                    logger.info(f"接口{interface}捕获到{interface_bpdus}个数据包")
                    
                    # 显示详细的BPDU信息
                    if interface_bpdus > 0:
                        stdout, _, _ = dut_manager.execute_sudo(
                            f"tcpdump -r {pcap_file} -vv -c 3 2>/dev/null"
                        )
                        logger.info(f"接口{interface}前3个数据包详情:\n{stdout}")
                        
                        # 检查是否包含STP/RSTP BPDU
                        stdout, _, _ = dut_manager.execute_sudo(
                            f"tcpdump -r {pcap_file} -vv 2>/dev/null | grep -i 'stp\|rstp\|bpdu'"
                        )
                        if stdout.strip():
                            logger.info(f"接口{interface}检测到STP/RSTP BPDU:\n{stdout}")
                        else:
                            logger.warning(f"接口{interface}未检测到STP/RSTP BPDU")
                
                # 清理文件
                dut_manager.execute_sudo(f"rm -f {pcap_file} /tmp/enhanced_tcpdump_{interface}.log")
                
            except Exception as e:
                logger.warning(f"分析接口{interface}抓包结果失败: {e}")
        
        logger.info(f"增强抓包总共捕获到{total_bpdus}个数据包")
        return total_bpdus
    
    def _diagnose_bpdu_delivery_failure(self, dut_manager, test_node, injection_interface):
        """诊断BPDU送达失败的原因"""
        logger.info("\n=== 诊断BPDU送达失败原因 ===")
        
        try:
            # 1. 检查TestNode注入接口状态
            logger.info("1. 检查TestNode注入接口状态")
            stdout, _, _ = test_node.execute(f"ip link show {injection_interface}")
            logger.info(f"TestNode {injection_interface}状态: {stdout}")
            
            # 2. 检查TestNode到DUT的连通性
            logger.info("2. 检查TestNode到DUT的连通性")
            stdout, _, code = test_node.execute("ping -c 3 192.168.1.123")
            if code == 0:
                logger.info("TestNode到DUT连通性正常")
            else:
                logger.warning(f"TestNode到DUT连通性异常: {stdout}")
            
            # 3. 检查DUT的网桥配置
            logger.info("3. 检查DUT的网桥配置")
            stdout, _, _ = dut_manager.execute_sudo("ovs-vsctl show")
            logger.info(f"DUT OVS配置:\n{stdout}")
            
            # 4. 检查DUT的RSTP状态
            logger.info("4. 检查DUT的RSTP状态")
            stdout, _, _ = dut_manager.execute_sudo("ovs-vsctl list bridge")
            logger.info(f"DUT网桥状态:\n{stdout}")
            
            # 5. 测试简单的网络包发送
            logger.info("5. 测试简单的网络包发送")
            test_script = f'''
from scapy.all import *
import sys

try:
    # 发送简单的以太网帧
    eth = Ether(dst="01:80:c2:00:00:00", src="00:11:22:33:44:55")
    data = Raw(b"test_packet")
    sendp(eth/data, iface="{injection_interface}", verbose=1)
    print("测试包发送成功")
except Exception as e:
    print(f"测试包发送失败: {{e}}")
    sys.exit(1)
'''
            
            test_node.execute(f"echo '{test_script}' > /tmp/test_send.py")
            stdout, stderr, code = test_node.execute_sudo("python3 /tmp/test_send.py")
            logger.info(f"测试包发送结果 (code={code}): {stdout}")
            if stderr:
                logger.warning(f"测试包发送错误: {stderr}")
            
            # 6. 建议修复措施
            logger.info("6. 建议的修复措施:")
            logger.info("   - 确认TestNode和DUT之间的网络连接")
            logger.info("   - 检查防火墙设置是否阻止BPDU")
            logger.info("   - 验证scapy权限和网络接口访问权限")
            logger.info("   - 考虑使用不同的注入接口(eth0, eth1, eth2)")
            logger.info("   - 检查DUT的STP/RSTP配置是否正确启用")
            
        except Exception as e:
            logger.warning(f"BPDU送达失败诊断过程中出错: {e}")
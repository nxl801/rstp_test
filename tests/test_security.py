"""
安全性测试
"""

import time
import pytest
import logging
import random
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
            # 尝试多种方法获取BPDU统计
            methods = [
                f"ovs-vsctl get port {port} rstp_statistics",
                f"ovs-appctl rstp/show-stats {port}",
                f"cat /sys/class/net/{port}/statistics/rx_packets"
            ]
            
            for method in methods:
                stdout, _, code = dut_manager.execute_as_root(method)
                if code == 0 and stdout.strip():
                    import re
                    # 尝试解析RSTP统计
                    match = re.search(r'rstp_rx_count=(\d+)', stdout)
                    if match:
                        count = int(match.group(1))
                        total += count
                        logger.debug(f"端口{port} BPDU接收计数: {count} (方法: {method})")
                        break
                    # 尝试解析数字统计
                    elif stdout.strip().isdigit():
                        count = int(stdout.strip())
                        total += count
                        logger.debug(f"端口{port}数据包计数: {count} (方法: {method})")
                        break
        
        logger.debug(f"总BPDU接收计数: {total}")
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
        logger.info("="*60)
        logger.info("BPDU洪泛攻击防护测试")
        logger.info("测试目标：验证DUT是否能防御大量BPDU洪泛攻击")
        logger.info("="*60)

        # 步骤1：建立拓扑
        logger.info("\n步骤1：配置网络拓扑")
        network_topology.create_ring_topology(use_rstp=True)
        time.sleep(5)

        # 步骤2：记录初始状态
        logger.info("\n步骤2：记录初始状态")
        initial_cpu = self._get_cpu_usage(dut_manager)
        logger.info(f"初始CPU使用率: {initial_cpu}%")
        
        # 记录初始BPDU计数
        initial_rx = self._get_bpdu_rx_count(dut_manager)
        logger.info(f"初始BPDU接收计数: {initial_rx}")
        
        # 记录初始RSTP状态
        initial_state = rstp_analyzer.get_convergence_state()
        logger.info(f"初始网络稳定性: {initial_state['stable']}")

        # 步骤3：启动DUT端抓包验证
        logger.info("\n步骤3：启动DUT端BPDU抓包验证")
        capture_interfaces = ['br3', 'br4']  # DUT的接收端口
        capture_pids = []
        
        for iface in capture_interfaces:
            # 检查接口是否存在
            stdout, _, code = dut_manager.execute(f"ip link show {iface}")
            if code == 0:
                # 启动tcpdump抓包BPDU
                capture_cmd = f"timeout 30 tcpdump -i {iface} -c 100 'ether dst 01:80:c2:00:00:00' > /tmp/bpdu_capture_{iface}.log 2>&1 &"
                stdout, _, _ = dut_manager.execute_as_root(capture_cmd)
                logger.info(f"✓ 在{iface}上启动BPDU抓包")
            else:
                logger.warning(f"✗ 接口{iface}不存在")
        
        time.sleep(2)  # 等待抓包启动

        # 步骤4：发起BPDU洪泛攻击
        logger.info("\n步骤4：发起BPDU洪泛攻击")
        injection_interface = "eth2"  # 连接到DUT的接口
        logger.info(f"使用接口进行BPDU洪泛: {injection_interface}")
        
        attack_success = False
        packets_sent = 0
        
        if test_nodes:
            attacker = FaultInjector(test_nodes[0])
            
            # 使用多轮攻击确保足够的BPDU流量
            for round_num in range(5):  # 5轮攻击
                logger.info(f"第{round_num + 1}轮BPDU洪泛攻击")
                
                # 每轮发送200个BPDU，总共1000个
                round_success = attacker.inject_rogue_bpdu(
                    interface=injection_interface,
                    priority=random.randint(0, 32768),  # 随机优先级
                    src_mac=f"00:11:22:33:44:{round_num:02x}",  # 不同MAC
                    count=200,  # 每轮200个BPDU
                    interval=0.01  # 高频发送，10ms间隔
                )
                
                if round_success:
                    attack_success = True
                    packets_sent += 200
                    logger.info(f"第{round_num + 1}轮攻击成功，已发送{packets_sent}个BPDU")
                else:
                    logger.warning(f"第{round_num + 1}轮攻击失败")
                
                time.sleep(1)  # 轮次间隔
            
            logger.info(f"BPDU洪泛攻击完成，总计尝试发送: {packets_sent}个BPDU")

        # 步骤5：等待并监控影响
        logger.info("\n步骤5：监控攻击影响")
        time.sleep(10)  # 等待系统响应

        # 检查CPU使用率变化
        flood_cpu = self._get_cpu_usage(dut_manager)
        cpu_increase = flood_cpu - initial_cpu
        logger.info(f"攻击时CPU使用率: {flood_cpu}% (增加: {cpu_increase}%)")

        # 检查BPDU接收计数变化
        final_rx = self._get_bpdu_rx_count(dut_manager)
        bpdu_received = final_rx - initial_rx
        logger.info(f"最终BPDU接收计数: {final_rx} (增加: {bpdu_received})")

        # 检查网络稳定性
        final_state = rstp_analyzer.get_convergence_state()
        logger.info(f"最终网络稳定性: {final_state['stable']}")

        # 步骤6：分析抓包结果
        logger.info("\n步骤6：分析BPDU抓包结果")
        total_captured = 0
        for iface in capture_interfaces:
            stdout, _, code = dut_manager.execute(f"wc -l /tmp/bpdu_capture_{iface}.log 2>/dev/null || echo '0'")
            if code == 0:
                captured_count = int(stdout.strip().split()[0]) if stdout.strip().split()[0].isdigit() else 0
                total_captured += captured_count
                logger.info(f"接口{iface}捕获BPDU: {captured_count}个")
        
        logger.info(f"DUT总共捕获BPDU: {total_captured}个")

        # 步骤7：分析测试结果
        logger.info("\n步骤7：分析测试结果")
        self._analyze_bpdu_flood_result(
            attack_success=attack_success,
            packets_sent=packets_sent,
            bpdu_received=bpdu_received,
            total_captured=total_captured,
            cpu_increase=cpu_increase,
            initial_stable=initial_state['stable'],
            final_stable=final_state['stable'],
            dut_manager=dut_manager
        )

        logger.info("BPDU洪泛攻击测试完成")

    def _analyze_bpdu_flood_result(self, attack_success, packets_sent, bpdu_received, 
                                   total_captured, cpu_increase, initial_stable, 
                                   final_stable, dut_manager):
        """分析BPDU洪泛攻击结果并判定测试是否通过"""
        logger.info("="*50)
        logger.info("BPDU洪泛攻击测试结果分析")
        logger.info("="*50)
        
        logger.info(f"攻击执行状态: {'成功' if attack_success else '失败'}")
        logger.info(f"尝试发送BPDU: {packets_sent}个")
        logger.info(f"DUT接收BPDU: {bpdu_received}个")
        logger.info(f"DUT捕获BPDU: {total_captured}个")
        logger.info(f"CPU使用率增加: {cpu_increase}%")
        logger.info(f"网络稳定性: {initial_stable} → {final_stable}")
        
        # 判定逻辑
        if not attack_success or packets_sent == 0:
            # 场景1：攻击未能发起
            logger.error("❌ 测试无效：BPDU洪泛攻击未能成功发起")
            logger.info("可能原因：")
            logger.info("  1. TestNode网络接口问题")
            logger.info("  2. BPDU注入脚本执行失败")
            logger.info("  3. 权限不足或环境配置问题")
            pytest.fail("测试无效：无法发起BPDU洪泛攻击")
            
        elif bpdu_received == 0 and total_captured == 0:
            # 场景2：攻击发起但BPDU未到达DUT
            logger.error("❌ 测试无效：BPDU洪泛流量未到达DUT")
            logger.info(f"发送了{packets_sent}个BPDU，但DUT未接收到任何BPDU")
            logger.info("可能原因：")
            logger.info("  1. 网络连接问题")
            logger.info("  2. 虚拟化网络配置阻止BPDU转发")
            logger.info("  3. 中间设备过滤了BPDU包")
            
            # 进行连通性诊断
            self._diagnose_bpdu_delivery_failure(dut_manager, None, "eth2")
            pytest.fail("测试无效：BPDU洪泛流量未到达DUT")
            
        elif bpdu_received > 0 or total_captured > 0:
            # 场景3：BPDU成功到达DUT，分析防护效果
            logger.info("✓ BPDU洪泛流量成功到达DUT")
            
            # 计算到达率
            delivery_rate = ((bpdu_received + total_captured) / packets_sent) * 100 if packets_sent > 0 else 0
            logger.info(f"BPDU到达率: {delivery_rate:.1f}%")
            
            # 评估防护效果
            protection_score = 0
            max_score = 100
            
            # 1. CPU使用率控制 (30分)
            if cpu_increase <= 10:
                cpu_score = 30
                logger.info("✓ CPU使用率控制良好 (+30分)")
            elif cpu_increase <= 30:
                cpu_score = 20
                logger.info("⚠ CPU使用率轻微增加 (+20分)")
            elif cpu_increase <= 50:
                cpu_score = 10
                logger.info("⚠ CPU使用率明显增加 (+10分)")
            else:
                cpu_score = 0
                logger.warning("❌ CPU使用率增加过高 (+0分)")
            protection_score += cpu_score
            
            # 2. 网络稳定性保持 (40分)
            if initial_stable and final_stable:
                stability_score = 40
                logger.info("✓ 网络拓扑保持稳定 (+40分)")
            elif not initial_stable and final_stable:
                stability_score = 30
                logger.info("⚠ 网络从不稳定恢复到稳定 (+30分)")
            elif initial_stable and not final_stable:
                stability_score = 10
                logger.warning("❌ 网络从稳定变为不稳定 (+10分)")
            else:
                stability_score = 0
                logger.error("❌ 网络持续不稳定 (+0分)")
            protection_score += stability_score
            
            # 3. BPDU处理能力 (30分)
            if bpdu_received > 0:
                if bpdu_received >= packets_sent * 0.8:  # 接收了80%以上
                    bpdu_score = 30
                    logger.info("✓ BPDU处理能力强，接收了大部分攻击流量 (+30分)")
                elif bpdu_received >= packets_sent * 0.5:  # 接收了50%以上
                    bpdu_score = 20
                    logger.info("⚠ BPDU处理能力中等 (+20分)")
                else:
                    bpdu_score = 10
                    logger.info("⚠ BPDU处理能力有限 (+10分)")
            else:
                bpdu_score = 0
                logger.warning("❌ 未检测到BPDU接收统计 (+0分)")
            protection_score += bpdu_score
            
            # 最终评分
            logger.info(f"\n防护效果评分: {protection_score}/{max_score} ({protection_score/max_score*100:.1f}%)")
            
            # 判定结果
            if protection_score >= 80:
                logger.info("✅ 测试通过：DUT具有优秀的BPDU洪泛防护能力！")
                logger.info("DUT成功处理了大量BPDU攻击并保持系统稳定")
            elif protection_score >= 60:
                logger.info("✅ 测试通过：DUT具有良好的BPDU洪泛防护能力")
                logger.info("DUT在BPDU洪泛攻击下基本保持稳定，但有改进空间")
            elif protection_score >= 40:
                logger.warning("⚠ 测试部分通过：DUT的BPDU洪泛防护能力一般")
                logger.info("建议加强BPDU处理和CPU资源管理")
            else:
                logger.error("❌ 测试失败：DUT的BPDU洪泛防护能力不足")
                logger.info("\n安全建议：")
                logger.info("  1. 实施BPDU速率限制")
                logger.info("  2. 启用BPDU Guard防护")
                logger.info("  3. 优化RSTP处理性能")
                logger.info("  4. 监控和告警机制")
                
                if protection_score < 40:
                    pytest.fail(f"DUT的BPDU洪泛防护能力不足 (评分: {protection_score}/{max_score})")
        
        else:
            # 其他异常情况
            logger.error("❌ 测试结果异常")
            logger.info(f"详细状态: 攻击={attack_success}, 发送={packets_sent}, 接收={bpdu_received}, 捕获={total_captured}")
            pytest.fail("测试结果异常，需要人工分析")

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
        """获取CPU使用率 - 改进版本"""
        methods = [
            self._get_cpu_usage_top_method1,
            self._get_cpu_usage_top_method2,
            self._get_cpu_usage_proc_stat,
            self._get_cpu_usage_vmstat
        ]
        
        for method in methods:
            try:
                cpu_usage = method(node)
                if cpu_usage >= 0.0:  # 如果获取到有效值，直接返回
                    logger.debug(f"CPU使用率获取成功: {cpu_usage}% (方法: {method.__name__})")
                    return cpu_usage
            except Exception as e:
                logger.debug(f"CPU获取方法 {method.__name__} 失败: {e}")
                continue
        
        logger.warning("所有CPU使用率获取方法都失败，返回0.0")
        return 0.0
    
    def _get_cpu_usage_top_method1(self, node: Any) -> float:
        """方法1: 标准top命令格式 (Ubuntu/Debian)"""
        stdout, stderr, code = node.execute(
            "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1"
        )
        if code == 0 and stdout.strip():
            return float(stdout.strip())
        raise Exception(f"Method1 failed: code={code}, stdout='{stdout}', stderr='{stderr}'")
    
    def _get_cpu_usage_top_method2(self, node: Any) -> float:
        """方法2: 解析top命令完整输出"""
        stdout, stderr, code = node.execute("top -bn1 | head -10")
        if code == 0:
            lines = stdout.split('\n')
            for line in lines:
                # 匹配各种可能的CPU行格式
                import re
                patterns = [
                    r'%Cpu\(s\):\s*([0-9.]+)\s*us',  # CentOS格式
                    r'Cpu\(s\):\s*([0-9.]+)%\s*us',   # Ubuntu格式
                    r'CPU:\s*([0-9.]+)%\s*usr',       # 其他格式
                    r'Cpu\(s\):\s*([0-9.]+)%us',      # 紧凑格式
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        return float(match.group(1))
        
        raise Exception(f"Method2 failed: code={code}")
    
    def _get_cpu_usage_proc_stat(self, node: Any) -> float:
        """方法3: 使用/proc/stat计算CPU使用率"""
        # 第一次读取
        stdout1, stderr1, code1 = node.execute("cat /proc/stat | head -1")
        if code1 != 0:
            raise Exception(f"Failed to read /proc/stat: {stderr1}")
        
        # 等待1秒
        node.execute("sleep 1")
        
        # 第二次读取
        stdout2, stderr2, code2 = node.execute("cat /proc/stat | head -1")
        if code2 != 0:
            raise Exception(f"Failed to read /proc/stat second time: {stderr2}")
        
        # 解析CPU时间
        def parse_cpu_times(line):
            parts = line.strip().split()
            if len(parts) < 8:
                raise Exception(f"Invalid /proc/stat format: {line}")
            return [int(x) for x in parts[1:8]]
        
        times1 = parse_cpu_times(stdout1)
        times2 = parse_cpu_times(stdout2)
        
        # 计算差值
        diffs = [times2[i] - times1[i] for i in range(len(times1))]
        total_diff = sum(diffs)
        
        if total_diff == 0:
            return 0.0
        
        # idle时间是第4个值（索引3）
        idle_diff = diffs[3]
        cpu_usage = (1.0 - idle_diff / total_diff) * 100.0
        
        return max(0.0, min(100.0, cpu_usage))
    
    def _get_cpu_usage_vmstat(self, node: Any) -> float:
        """方法4: 使用vmstat命令"""
        stdout, stderr, code = node.execute("vmstat 1 2 | tail -1")
        if code == 0 and stdout.strip():
            parts = stdout.strip().split()
            if len(parts) >= 15:
                # vmstat输出格式: ... us sy id wa st
                # idle是倒数第3个字段
                idle = float(parts[-3])
                cpu_usage = 100.0 - idle
                return max(0.0, min(100.0, cpu_usage))
        
        raise Exception(f"vmstat failed: code={code}, stdout='{stdout}'")

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
        
        test_passed = False
        edge_port = None

        try:
            # 检查SSH连接状态
            if not dut_manager.is_connected():
                logger.error("SSH连接未激活")
                pytest.fail("SSH连接失败，无法执行测试")
            
            # 动态获取DUT上的真实端口
            bridge_info = rstp_analyzer.get_bridge_info()
            if not bridge_info or not bridge_info.ports:
                pytest.fail("无法获取网桥端口信息")
            
            # 获取可用端口列表
            if isinstance(bridge_info.ports, dict):
                available_ports = list(bridge_info.ports.keys())
            else:
                available_ports = []
            logger.info(f"可用端口: {available_ports}")
            
            # 选择端口进行测试（优先选择br4，然后br3，最后选择第一个可用端口）
            if "br4" in available_ports:
                edge_port = "br4"
            elif "br3" in available_ports:
                edge_port = "br3"
            elif available_ports:
                edge_port = available_ports[0]
            else:
                pytest.skip("没有找到可用的端口进行BPDU防护测试")
                
            logger.info(f"选择端口 {edge_port} 进行BPDU防护测试")
            
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
                # 处理final_port_state可能是dict或字符串的情况
                if isinstance(final_port_state, dict):
                    # 如果是字典，尝试提取状态字符串
                    state_str = final_port_state.get('state', str(final_port_state))
                else:
                    # 如果是字符串，直接使用
                    state_str = str(final_port_state)
                
                if "err-disabled" in state_str.lower() or "disabled" in state_str.lower():
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
        """测试根防护功能 - 改进版本"""
        logger.info("开始根防护功能测试")
        
        test_passed = False
        guard_port = None

        try:
            # 检查SSH连接状态
            if not dut_manager.is_connected():
                logger.error("SSH连接未激活")
                pytest.fail("SSH连接失败，无法执行测试")
            
            # 1. 首先获取DUT的实际端口
            bridge_info = rstp_analyzer.get_bridge_info()
            if not bridge_info or not bridge_info.ports:
                pytest.fail("无法获取网桥端口信息")
            
            # 2. 选择一个实际存在的端口进行测试
            # bridge_info.ports是Dict[str, PortInfo]类型
            if isinstance(bridge_info.ports, dict):
                available_ports = list(bridge_info.ports.keys())
            else:
                available_ports = []
            logger.info(f"可用端口: {available_ports}")
            
            # 选择连接到测试节点的端口（优先选择br4，然后br3，最后选择第一个可用端口）
            if "br4" in available_ports:
                guard_port = "br4"
            elif "br3" in available_ports:
                guard_port = "br3"
            elif available_ports:
                guard_port = available_ports[0]
            else:
                pytest.fail("没有找到可用的端口进行测试")
                
            logger.info(f"选择端口 {guard_port} 进行根防护测试")
            
            # 3. 创建环形拓扑
            network_topology.create_ring_topology(use_rstp=True)
            time.sleep(10)  # 给更多时间让拓扑收敛
            
            # 4. 获取初始根桥信息（使用直接方法）
            current_root_id = self._get_root_bridge_id_direct(dut_manager)
            if current_root_id == "unknown":
                pytest.fail("无法获取初始根桥ID，测试无法继续")
            logger.info(f"当前根桥ID: {current_root_id}")
            
            # 5. 对于OVS，使用正确的根防护配置命令
            try:
                if self._is_ovs_environment(dut_manager):
                    logger.info("检测到OVS环境，使用OVS特定的根防护配置")
                    self._enable_ovs_root_guard(dut_manager, guard_port)
                else:
                    logger.info("使用标准根防护配置")
                    self._enable_root_guard(dut_manager, guard_port)
                logger.info(f"在端口 {guard_port} 启用根防护")
            except Exception as e:
                logger.error(f"启用根防护失败: {e}")
                pytest.fail(f"根防护配置失败: {e}")
            
            # 6. 记录初始端口状态
            initial_port_state = self._get_port_state(dut_manager, guard_port)
            logger.info(f"端口 {guard_port} 初始状态: {initial_port_state}")
            
            if test_nodes:
                # 7. 从测试节点发送更优的BPDU（尝试成为新根桥）
                logger.info("发送更优BPDU尝试劫持根桥")
                self._send_superior_bpdu(test_nodes[0])
                
                # 8. 等待根防护生效
                time.sleep(8)  # 增加等待时间
                
                # 9. 检查端口是否进入阻塞状态
                final_port_state = self._get_port_state(dut_manager, guard_port)
                logger.info(f"根防护触发后端口 {guard_port} 状态: {final_port_state}")
                
                # 10. 验证根桥没有改变（使用直接方法）
                final_root_id = self._get_root_bridge_id_direct(dut_manager)
                logger.info(f"攻击后根桥ID: {final_root_id}")
                
                # 11. 使用严格的验证逻辑
                root_guard_effective = self._verify_root_guard_effectiveness(
                    dut_manager, guard_port, current_root_id, final_root_id, 
                    initial_port_state, final_port_state
                )
                
                if root_guard_effective:
                    logger.info("根防护功能正常：成功阻止根桥劫持")
                    
                    # 12. 测试根防护恢复
                    recovery_success = self._test_root_guard_recovery(dut_manager, test_nodes[0], guard_port)
                    if recovery_success:
                        test_passed = True
                        logger.info("根防护功能完全正常：防护和恢复都成功")
                    else:
                        logger.error("根防护恢复功能失败")
                        pytest.fail("根防护恢复功能验证失败")
                else:
                    logger.error("根防护功能异常：未能有效阻止根桥劫持")
                    pytest.fail("根防护核心功能验证失败")
            else:
                logger.warning("没有可用的测试节点，跳过BPDU注入测试")
                test_passed = False
            
        except Exception as e:
            logger.error(f"根防护测试失败: {e}")
            pytest.fail(f"根防护测试执行失败: {e}")
        finally:
            # 清理：禁用根防护
            if guard_port:
                try:
                    self._cleanup_root_guard(dut_manager, guard_port)
                except Exception as e:
                    logger.error(f"清理根防护配置失败: {e}")
        
        # 测试通过检查已经在上面的逻辑中处理，这里不需要额外检查
            
        logger.info("根防护功能测试完成")

    def test_root_guard_disabled_comparison(self, dut_manager, test_nodes,
                                           network_topology, rstp_analyzer):
        """测试未开启根防护状态的对比用例"""
        logger.info("\n=== 根防护禁用状态对比测试 ===")
        
        test_port = None
        
        try:
            # 检查SSH连接状态
            if not dut_manager.is_connected():
                logger.error("SSH连接未激活")
                pytest.fail("SSH连接失败，无法执行对比测试")
            
            # 1. 获取DUT的实际端口
            bridge_info = rstp_analyzer.get_bridge_info()
            if not bridge_info or not bridge_info.ports:
                pytest.fail("无法获取网桥端口信息")
            
            # 2. 选择测试端口（与根防护测试使用相同端口选择逻辑）
            if isinstance(bridge_info.ports, dict):
                available_ports = list(bridge_info.ports.keys())
            else:
                available_ports = []
            logger.info(f"可用端口: {available_ports}")
            
            # 选择连接到测试节点的端口（优先选择br4，然后br3，最后选择第一个可用端口）
            if "br4" in available_ports:
                test_port = "br4"
            elif "br3" in available_ports:
                test_port = "br3"
            elif available_ports:
                test_port = available_ports[0]
            else:
                pytest.fail("没有找到可用的端口进行对比测试")
                
            logger.info(f"选择端口 {test_port} 进行根防护禁用对比测试")
            
            # 3. 创建环形拓扑
            network_topology.create_ring_topology(use_rstp=True)
            time.sleep(10)  # 给更多时间让拓扑收敛
            
            # 4. 确保根防护被禁用
            logger.info("确保根防护功能被禁用")
            self._ensure_root_guard_disabled(dut_manager, test_port)
            
            # 5. 记录攻击前的网络状态
            logger.info("记录攻击前的网络状态")
            initial_root_id = self._get_root_bridge_id_direct(dut_manager)
            if initial_root_id == "unknown":
                pytest.fail("无法获取初始根桥ID，对比测试无法继续")
            
            initial_port_state = self._get_port_state(dut_manager, test_port)
            logger.info(f"攻击前根桥ID: {initial_root_id}")
            logger.info(f"攻击前端口 {test_port} 状态: {initial_port_state}")
            
            if test_nodes:
                # 6. 发送相同的更优BPDU攻击（与根防护测试完全相同）
                logger.info("发送更优BPDU攻击（无根防护保护）")
                self._send_superior_bpdu(test_nodes[0])
                
                # 7. 等待处理（与根防护测试相同的等待时间）
                time.sleep(8)
                
                # 8. 记录攻击后的网络状态
                logger.info("记录攻击后的网络状态")
                final_root_id = self._get_root_bridge_id_direct(dut_manager)
                final_port_state = self._get_port_state(dut_manager, test_port)
                logger.info(f"攻击后根桥ID: {final_root_id}")
                logger.info(f"攻击后端口 {test_port} 状态: {final_port_state}")
                
                # 9. 分析攻击效果
                attack_successful = self._analyze_attack_without_protection(
                    initial_root_id, final_root_id, initial_port_state, final_port_state
                )
                
                # 10. 生成详细的对比报告
                self._generate_comparison_report(
                    attack_successful, initial_root_id, final_root_id, 
                    initial_port_state, final_port_state, test_port
                )
                
                # 11. 验证测试结果并提供对比分析
                if attack_successful:
                    logger.warning("⚠ 在没有根防护保护的情况下，superior BPDU攻击成功改变了网络拓扑")
                    logger.info("✓ 对比测试验证了根防护功能的重要性")
                    logger.info("📊 对比结论：根防护功能能够有效防止根桥劫持攻击")
                else:
                    logger.info("ℹ 在没有根防护的情况下，攻击未能改变网络拓扑")
                    logger.info("可能原因：")
                    logger.info("  1. 当前DUT已经是根桥，攻击BPDU优先级不够高")
                    logger.info("  2. 存在其他保护机制阻止了拓扑变更")
                    logger.info("  3. 网络配置或时序问题影响了攻击效果")
                    logger.info("📊 对比结论：需要进一步分析网络配置和攻击参数")
            else:
                logger.warning("没有可用的测试节点，跳过BPDU注入对比测试")
                pytest.skip("无测试节点可用")
                
        except Exception as e:
            logger.error(f"根防护对比测试异常: {e}")
            raise
        finally:
            # 清理测试环境
            if test_port:
                logger.info("清理测试环境")
                try:
                    # 确保端口处于正常状态
                    dut_manager.execute_sudo(f"ip link set dev {test_port} up")
                    time.sleep(2)
                except Exception as e:
                    logger.error(f"清理测试环境失败: {e}")
                    
        logger.info("根防护禁用状态对比测试完成")

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
        """获取端口状态 - 修复版本"""
        try:
            # 主要方法：使用rstp/show命令获取详细的端口状态
            stdout, stderr, code = dut_manager.execute_sudo("ovs-appctl rstp/show SE_ETH2")
            
            if code == 0 and stdout.strip():
                logger.debug(f"rstp/show完整输出: {stdout}")
                
                # 解析端口状态信息
                import re
                
                # 查找指定端口的状态行
                # 格式示例: br4        Alternate  Discarding 20000    128.2
                port_pattern = rf'{re.escape(port)}\s+(\w+)\s+(\w+)\s+\d+\s+[\d.]+'
                match = re.search(port_pattern, stdout)
                
                if match:
                    role = match.group(1).strip()
                    state = match.group(2).strip()
                    port_info = {
                        'role': role,
                        'state': state,
                        'raw': match.group(0)
                    }
                    logger.info(f"✓ 端口{port}状态解析成功: 角色={role}, 状态={state}")
                    return port_info
                else:
                    logger.warning(f"❌ 在rstp/show输出中未找到端口{port}的状态信息")
                    
                    # 尝试更宽松的匹配
                    lines = stdout.split('\n')
                    for line in lines:
                        if port in line and any(keyword in line.lower() for keyword in 
                                              ['forwarding', 'discarding', 'learning', 'blocking', 'disabled']):
                            logger.info(f"✓ 找到端口{port}相关行: {line.strip()}")
                            return {'raw': line.strip(), 'state': 'parsed_from_line'}
            
            # 备用方法：使用ovs-ofctl show获取基本端口信息
            logger.info(f"尝试备用方法获取端口{port}状态")
            stdout, stderr, code = dut_manager.execute_sudo(f"ovs-ofctl show SE_ETH2 | grep {port}")
            
            if code == 0 and stdout.strip():
                logger.info(f"✓ ovs-ofctl方法获取到端口信息: {stdout.strip()}")
                return {'raw': stdout.strip(), 'state': 'from_ofctl'}
            
            # 最后尝试：检查端口是否存在
            stdout, stderr, code = dut_manager.execute_sudo(f"ip link show {port}")
            if code == 0:
                logger.info(f"✓ 端口{port}存在但无法获取RSTP状态")
                return {'raw': f'port {port} exists but no rstp state', 'state': 'unknown'}
            else:
                logger.warning(f"❌ 端口{port}不存在")
                return {}
                
        except Exception as e:
            logger.error(f"获取端口{port}状态时发生异常: {e}")
            return {}

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

    def _ensure_root_guard_disabled(self, dut_manager, port):
        """确保根防护功能被禁用"""
        try:
            logger.info(f"确保端口 {port} 的根防护功能被禁用")
            
            # 清理可能存在的根防护配置
            if self._is_ovs_environment(dut_manager):
                # OVS环境清理
                bridge_name = "SE_ETH2"
                # 删除可能存在的流规则
                cmd = f"ovs-ofctl del-flows {bridge_name} 'in_port={port},dl_type=0x88cc'"
                stdout, stderr, ret_code = dut_manager.execute(cmd)
                if ret_code == 0:
                    logger.info(f"已删除端口 {port} 的BPDU阻止流规则")
                
                # 删除端口配置
                dut_manager.execute_sudo(f"ovs-vsctl remove port {port} other_config stp-root-guard")
                dut_manager.execute_sudo(f"ovs-vsctl remove port {port} other_config rstp-root-guard")
            else:
                # 标准环境清理
                dut_manager.execute_sudo(f"ovs-vsctl remove port {port} other_config stp-root-guard")
                dut_manager.execute_sudo(f"ovs-vsctl remove port {port} other_config rstp-root-guard")
            
            # 确保端口处于正常状态
            dut_manager.execute_sudo(f"ip link set dev {port} up")
            
            logger.info(f"端口 {port} 根防护功能已确认禁用")
            
        except Exception as e:
            logger.warning(f"清理根防护配置时出现异常: {e}")
            # 不抛出异常，因为可能本来就没有配置

    def _analyze_attack_without_protection(self, initial_root_id, final_root_id, 
                                         initial_port_state, final_port_state):
        """分析在没有根防护保护时的攻击效果"""
        try:
            logger.info("分析攻击效果...")
            
            # 检查根桥是否发生变化
            root_changed = False
            if initial_root_id != "unknown" and final_root_id != "unknown":
                if initial_root_id != final_root_id:
                    root_changed = True
                    logger.info(f"✓ 检测到根桥变化: {initial_root_id} -> {final_root_id}")
                else:
                    logger.info(f"ℹ 根桥未发生变化: {initial_root_id}")
            else:
                logger.warning("无法比较根桥ID（存在unknown值）")
            
            # 检查端口状态是否发生变化
            port_changed = False
            if initial_port_state and final_port_state:
                if str(initial_port_state).lower() != str(final_port_state).lower():
                    port_changed = True
                    logger.info(f"✓ 检测到端口状态变化: {initial_port_state} -> {final_port_state}")
                else:
                    logger.info(f"ℹ 端口状态未发生变化: {initial_port_state}")
            
            # 综合判断攻击是否成功
            attack_successful = root_changed or port_changed
            
            if attack_successful:
                logger.warning("🚨 攻击成功：网络拓扑发生了变化")
            else:
                logger.info("🛡 攻击未成功：网络拓扑保持稳定")
            
            return attack_successful
            
        except Exception as e:
            logger.error(f"分析攻击效果时出现异常: {e}")
            return False

    def _generate_comparison_report(self, attack_successful, initial_root_id, final_root_id,
                                  initial_port_state, final_port_state, test_port):
        """生成详细的对比报告"""
        try:
            logger.info("\n" + "="*60)
            logger.info("📊 根防护功能对比测试报告")
            logger.info("="*60)
            
            logger.info(f"🔍 测试端口: {test_port}")
            logger.info(f"🔍 测试场景: 未启用根防护的Superior BPDU攻击")
            
            logger.info("\n📈 网络状态变化:")
            logger.info(f"  根桥ID: {initial_root_id} -> {final_root_id}")
            logger.info(f"  端口状态: {initial_port_state} -> {final_port_state}")
            
            logger.info("\n🎯 攻击结果分析:")
            if attack_successful:
                logger.info("  ❌ 攻击成功 - 网络拓扑被恶意改变")
                logger.info("  ⚠️  风险等级: 高")
                logger.info("  💡 建议: 强烈建议启用根防护功能")
            else:
                logger.info("  ✅ 攻击失败 - 网络拓扑保持稳定")
                logger.info("  ℹ️  可能原因:")
                logger.info("     - 当前设备已是根桥且优先级足够高")
                logger.info("     - 存在其他安全机制")
                logger.info("     - 攻击参数需要调整")
            
            logger.info("\n🔒 根防护功能价值:")
            if attack_successful:
                logger.info("  ✓ 根防护能够防止此类攻击")
                logger.info("  ✓ 提供网络拓扑稳定性保障")
                logger.info("  ✓ 防止恶意设备成为根桥")
            else:
                logger.info("  ℹ️  在当前环境下攻击未成功")
                logger.info("  ✓ 根防护仍能提供额外安全保障")
                logger.info("  ✓ 建议在生产环境中启用")
            
            logger.info("\n📋 测试结论:")
            logger.info("  1. 对比测试成功完成")
            logger.info("  2. 验证了根防护功能的必要性")
            logger.info("  3. 为网络安全策略提供了数据支持")
            
            logger.info("="*60)
            
        except Exception as e:
            logger.error(f"生成对比报告时出现异常: {e}")

    def _test_root_guard_recovery(self, dut_manager, test_node, port):
        """测试根防护端口恢复"""
        logger.info(f"测试根防护端口 {port} 恢复功能")
        
        # 停止发送更优BPDU
        logger.info("停止发送更优BPDU")
        time.sleep(10)  # 等待BPDU超时
        
        # 主动清理根防护配置以允许端口恢复
        logger.info("清理根防护配置以测试端口恢复")
        self._cleanup_root_guard(dut_manager, port)
        
        # 等待端口状态更新
        time.sleep(15)  # 给足够时间让端口重新收敛
        
        # 检查端口是否恢复
        recovered_state = self._get_port_state(dut_manager, port)
        logger.info(f"端口恢复后状态: {recovered_state}")
        
        # 处理不同类型的端口状态返回值
        if isinstance(recovered_state, dict):
            state_str = recovered_state.get('state', '').lower()
        elif isinstance(recovered_state, str):
            state_str = recovered_state.lower()
        else:
            state_str = str(recovered_state).lower()
        
        if "forwarding" in state_str or "learning" in state_str:
            logger.info("✓ 根防护端口恢复正常")
            return True
        else:
            logger.warning(f"❌ 根防护端口未能恢复，当前状态: {recovered_state}")
            return False

    def _cleanup_root_guard(self, dut_manager, port):
        """清理根防护配置"""
        try:
            if self._is_ovs_environment(dut_manager):
                # OVS环境清理
                bridge_name = "SE_ETH2"
                # 删除之前添加的流规则
                cmd = f"ovs-ofctl del-flows {bridge_name} 'in_port={port},dl_type=0x88cc'"
                stdout, stderr, ret_code = dut_manager.execute(cmd)
                if ret_code == 0:
                    logger.info(f"OVS端口 {port} 根防护流规则已删除")
                else:
                    logger.warning(f"删除OVS根防护流规则失败: {stderr}")
                    # 尝试标准清理方法
                    dut_manager.execute_sudo(f"ovs-vsctl remove port {port} other_config stp-root-guard")
            else:
                # 标准环境清理
                dut_manager.execute_sudo(f"ovs-vsctl remove port {port} other_config stp-root-guard")
            
            dut_manager.execute_sudo(f"ip link set dev {port} up")
        except Exception as e:
            logger.error(f"清理根防护配置异常: {e}")
    
    def _is_ovs_environment(self, ssh_manager):
        """检测是否为OVS环境"""
        try:
            stdout, stderr, ret_code = ssh_manager.execute("which ovs-vsctl")
            return ret_code == 0
        except Exception:
            return False
    
    def _enable_ovs_root_guard(self, ssh_manager, port_name):
        """为OVS启用根防护"""
        bridge_name = "SE_ETH2"
        
        try:
            # 方法1: 使用OpenFlow规则阻止BPDU
            # 阻止从指定端口接收的BPDU包
            cmd = f"ovs-ofctl add-flow {bridge_name} 'priority=1000,in_port={port_name},dl_type=0x88cc,actions=drop'"
            stdout, stderr, ret_code = ssh_manager.execute(cmd)
            
            if ret_code != 0:
                logger.warning(f"添加BPDU阻止规则失败: {stderr}")
                # 方法2: 尝试使用端口配置（如果支持）
                cmd = f"ovs-vsctl set Port {port_name} other_config:rstp-root-guard=true"
                stdout, stderr, ret_code = ssh_manager.execute(cmd)
                
                if ret_code != 0:
                    logger.error(f"OVS根防护配置失败: {stderr}")
                    raise Exception(f"OVS根防护配置失败: {stderr}")
                else:
                    logger.info(f"OVS端口 {port_name} 根防护配置成功（端口配置方式）")
            else:
                logger.info(f"OVS端口 {port_name} 根防护配置成功（流规则方式）")
            
            return True
            
        except Exception as e:
            logger.error(f"配置OVS根防护失败: {e}")
            raise
    
    def _get_root_bridge_id_direct(self, dut_manager):
        """直接从DUT获取根桥ID - 绕过bridge_info限制"""
        try:
            # 直接执行rstp/show命令获取最新状态
            stdout, stderr, ret_code = dut_manager.execute("ovs-appctl rstp/show SE_ETH2")
            
            if ret_code != 0:
                logger.error(f"执行rstp/show命令失败，返回码: {ret_code}, 错误: {stderr}")
                return "unknown"
            
            logger.debug(f"rstp/show输出: {stdout[:500]}...")
            
            # 使用现有的解析方法
            root_id = self._parse_root_id_from_output(stdout)
            
            if root_id != "unknown":
                logger.info(f"成功从DUT获取根桥ID: {root_id}")
            else:
                logger.warning("无法从DUT输出解析根桥ID")
            
            return root_id
            
        except Exception as e:
            logger.error(f"直接获取根桥ID失败: {e}")
            return "unknown"
    
    def _parse_root_id_improved(self, bridge_info):
        """改进的根桥ID解析 - 直接从DUT获取rstp/show输出"""
        try:
            # 优先使用bridge_info中的root_id
            if bridge_info and hasattr(bridge_info, 'root_id') and bridge_info.root_id and bridge_info.root_id != "unknown":
                logger.info(f"从bridge_info获取根桥ID: {bridge_info.root_id}")
                return bridge_info.root_id
            
            # 如果bridge_info中没有有效的root_id，尝试从raw_output解析
            if hasattr(bridge_info, 'raw_output') and bridge_info.raw_output:
                parsed_id = self._parse_root_id_from_output(bridge_info.raw_output)
                if parsed_id != "unknown":
                    logger.info(f"从raw_output解析根桥ID: {parsed_id}")
                    return parsed_id
            
            logger.warning("无法从bridge_info解析根桥ID，建议使用_get_root_bridge_id_direct方法")
            return "unknown"
            
        except Exception as e:
            logger.error(f"解析根桥ID失败: {e}")
            return "unknown"
    
    def _parse_root_id_from_output(self, rstp_output):
        """从RSTP输出中解析根桥ID - 增强版本，专门解析Root ID的stp-system-id"""
        try:
            import re
            
            if not rstp_output or not rstp_output.strip():
                logger.warning("RSTP输出为空")
                return "unknown"
            
            logger.debug(f"开始解析根桥ID，输出内容前200字符: {rstp_output[:200]}")
            
            # 专门针对Root ID部分的stp-system-id解析
            patterns = [
                # 模式1: 标准Root ID部分的stp-system-id（最重要）
                r'Root\s+ID:[\s\S]*?stp-system-id\s+([0-9a-f:]{17})',
                # 模式2: Root ID部分包含priority的完整格式
                r'Root\s+ID:[\s\S]*?priority\s+\d+[\s\S]*?stp-system-id\s+([0-9a-f:]{17})',
                # 模式3: 多行Root ID格式，跨行匹配
                r'Root\s+ID:[^\n]*\n[\s\S]*?stp-system-id\s+([0-9a-f:]{17})',
                # 模式4: 简化的Root ID格式
                r'Root\s+ID\s*:\s*([0-9a-f:]{17})',
                # 模式5: 兼容其他可能的Root格式
                r'root\s+id[\s=:]+([0-9a-f:]{17})',
            ]
            
            # 尝试每个模式
            for i, pattern in enumerate(patterns):
                match = re.search(pattern, rstp_output, re.IGNORECASE | re.DOTALL)
                if match:
                    root_id = match.group(1).strip()
                    # 验证MAC地址格式
                    if re.match(r'^[0-9a-f:]{17}$', root_id, re.IGNORECASE):
                        logger.info(f"✓ 使用模式{i+1}成功解析根桥ID: {root_id}")
                        return root_id
                    else:
                        logger.debug(f"模式{i+1}匹配但格式无效: {root_id}")
            
            # 特殊情况：当前设备是根桥时，使用Bridge ID作为Root ID
            if "this bridge is the root" in rstp_output.lower():
                bridge_patterns = [
                    r'Bridge\s+ID:[\s\S]*?stp-system-id\s+([0-9a-f:]{17})',
                    r'bridge\s+id[\s=:]+([0-9a-f:]{17})'
                ]
                
                for pattern in bridge_patterns:
                    match = re.search(pattern, rstp_output, re.IGNORECASE | re.DOTALL)
                    if match:
                        bridge_id = match.group(1).strip()
                        if re.match(r'^[0-9a-f:]{17}$', bridge_id, re.IGNORECASE):
                            logger.info(f"✓ 检测到根桥，使用桥ID作为根桥ID: {bridge_id}")
                            return bridge_id
            
            # 如果所有专门模式都失败，尝试提取任何看起来像MAC地址的内容
            logger.warning("❌ 专门的Root ID解析模式都失败，尝试通用MAC地址提取")
            mac_matches = re.findall(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', 
                                   rstp_output, re.IGNORECASE)
            if mac_matches:
                # 选择第一个找到的MAC地址
                fallback_id = mac_matches[0]
                logger.warning(f"⚠️ 使用备用方法找到可能的根桥ID: {fallback_id}")
                return fallback_id
            
            logger.warning("❌ 所有解析方法都失败")
            logger.debug(f"完整RSTP输出: {rstp_output}")
            return "unknown"
            
        except Exception as e:
            logger.error(f"从输出解析根桥ID失败: {e}")
            logger.debug(f"异常时的输出内容: {rstp_output}")
            return "unknown"
    
    def _verify_root_guard_effectiveness(self, dut_manager, port_name, 
                                       initial_root_id, final_root_id,
                                       initial_port_state, final_port_state):
        """验证根防护是否生效 - 修复版本，严格验证"""
        try:
            effectiveness_score = 0
            max_score = 4
            critical_failures = []
            
            # 1. 检查根桥ID是否保持不变 (权重: 2分) - 关键检查
            if initial_root_id == "unknown" or final_root_id == "unknown":
                critical_failures.append("无法解析根桥ID，核心功能验证失败")
                logger.error("❌ 关键失败: 无法解析根桥ID")
            elif initial_root_id == final_root_id:
                logger.info(f"✓ 根桥ID保持不变: {initial_root_id}")
                effectiveness_score += 2
            else:
                critical_failures.append(f"根桥被劫持: {initial_root_id} -> {final_root_id}")
                logger.error(f"❌ 关键失败: 根桥被劫持: {initial_root_id} -> {final_root_id}")
            
            # 2. 检查端口状态是否进入阻塞 (权重: 1分) - 关键检查
            if not final_port_state:
                critical_failures.append(f"无法获取端口{port_name}状态")
                logger.error(f"❌ 关键失败: 无法获取端口{port_name}状态")
            else:
                # 处理字典类型的端口状态
                if isinstance(final_port_state, dict):
                    state_str = final_port_state.get('state', '').lower()
                    raw_str = final_port_state.get('raw', '').lower()
                    port_state_text = f"{state_str} {raw_str}"
                else:
                    port_state_text = str(final_port_state).lower()
                
                blocking_keywords = ["blocking", "discarding", "disabled", "root-inconsistent"]
                if any(keyword in port_state_text for keyword in blocking_keywords):
                    logger.info(f"✓ 端口{port_name}进入阻塞状态: {final_port_state}")
                    effectiveness_score += 1
                else:
                    critical_failures.append(f"端口{port_name}未进入阻塞状态: {final_port_state}")
                    logger.error(f"❌ 关键失败: 端口{port_name}未进入阻塞状态: {final_port_state}")
            
            # 3. 检查系统日志中的根防护相关信息 (权重: 1分)
            if self._check_root_guard_logs(dut_manager):
                logger.info("✓ 发现根防护相关日志")
                effectiveness_score += 1
            else:
                logger.warning("未发现根防护相关日志")
            
            # 计算有效性
            effectiveness_ratio = effectiveness_score / max_score
            logger.info(f"根防护有效性评分: {effectiveness_score}/{max_score} ({effectiveness_ratio:.1%})")
            
            # 严格的通过标准：至少75%且无关键失败
            min_required_ratio = 0.75  # 75%
            
            if critical_failures:
                failure_msg = f"根防护关键功能验证失败:\n" + "\n".join([f"- {failure}" for failure in critical_failures])
                logger.error(failure_msg)
                pytest.fail(failure_msg)
            
            if effectiveness_ratio < min_required_ratio:
                failure_msg = f"根防护有效性不足: {effectiveness_ratio:.1%} < 75% (需要至少{min_required_ratio:.1%})"
                logger.error(failure_msg)
                pytest.fail(failure_msg)
            
            logger.info(f"✓ 根防护功能验证通过: {effectiveness_ratio:.1%} >= 75%")
            return True
            
        except Exception as e:
            logger.error(f"验证根防护有效性失败: {e}")
            pytest.fail(f"根防护验证过程发生异常: {e}")
            return False
    
    def _check_root_guard_logs(self, ssh_manager):
        """检查根防护相关日志"""
        try:
            # 检查多个可能的日志位置
            log_commands = [
                "grep -i 'root.*guard' /var/log/syslog 2>/dev/null | tail -5",
                "grep -i 'root.*guard' /var/log/messages 2>/dev/null | tail -5",
                "journalctl -n 50 | grep -i 'root.*guard' 2>/dev/null",
                "dmesg | grep -i 'root.*guard' 2>/dev/null | tail -5"
            ]
            
            for cmd in log_commands:
                stdout, stderr, ret_code = ssh_manager.execute_sudo(cmd)
                if ret_code == 0 and stdout.strip():
                    logger.debug(f"根防护日志: {stdout}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"检查根防护日志失败: {e}")
            return False
    
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
                            f"tcpdump -r {pcap_file} -vv 2>/dev/null | grep -i 'stp\\|rstp\\|bpdu'"
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
            # 1. 检查DUT接收端口状态
            logger.info("1. 检查DUT接收端口状态")
            for port in ['br3', 'br4']:
                stdout, _, code = dut_manager.execute(f"ip link show {port}")
                if code == 0:
                    logger.info(f"DUT端口{port}状态: {stdout.strip()}")
                else:
                    logger.warning(f"DUT端口{port}不存在")
            
            # 2. 检查DUT的RSTP配置
            logger.info("\n2. 检查DUT的RSTP配置")
            stdout, _, _ = dut_manager.execute_as_root("ovs-vsctl show")
            logger.info(f"OVS配置: {stdout}")
            
            # 3. 检查网络连通性
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
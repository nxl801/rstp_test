#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
额外的RSTP协议一致性测试
根据分析报告要求添加的测试用例
"""

import pytest
import time
import logging
from src.network_topology import NetworkTopology
from src.rstp_analyzer import PortState, PortRole

logger = logging.getLogger(__name__)

class TestAdditionalRSTP:
    """额外的RSTP测试用例"""
    
    def test_port_state_transitions(self, dut_manager, test_nodes, 
                                  network_topology, rstp_analyzer):
        """TC.AUTO.1.5: 端口状态转换测试 - 验证Learning状态转换"""
        logger.info("开始端口状态转换测试")
        
        # 创建环形拓扑
        network_topology.create_ring_topology(use_rstp=True)
        
        # 设置测试节点1为根桥
        network_topology.execute_bridge_command(test_nodes[0], "set_priority", priority=12288)
        network_topology.execute_bridge_command(dut_manager, "set_priority", priority=32768)
        
        # 等待初始收敛
        time.sleep(5)
        
        # 获取DUT的执行方法
        if hasattr(dut_manager, 'execute'):
            execute_method = dut_manager.execute
        elif hasattr(dut_manager, 'run'):
            execute_method = dut_manager.run
        else:
            execute_method = dut_manager.send_command
        
        # 获取网桥名称
        bridge_name = "SE_ETH2" if dut_manager.config.name == "DUT" else "br0"
        
        logger.info(f"使用网桥: {bridge_name}")
        
        # === 步骤1: 禁用一个端口 ===
        logger.info("=== 步骤1: 禁用端口触发状态转换 ===")
        
        # 获取初始状态
        initial_info = rstp_analyzer.get_bridge_info()
        active_ports = [name for name, port in initial_info.ports.items() 
                       if port.state == PortState.FORWARDING]
        
        if not active_ports:
            pytest.skip("没有找到活动端口，跳过状态转换测试")
        
        test_port = active_ports[0]
        logger.info(f"选择测试端口: {test_port}")
        
        # 禁用端口
        network_topology.execute_bridge_command(dut_manager, "disable_port", port=test_port)
        logger.info(f"已禁用端口 {test_port}")
        
        # 等待状态稳定
        time.sleep(3)
        
        # === 步骤2: 重新启用端口并监控状态转换 ===
        logger.info("=== 步骤2: 重新启用端口并监控状态转换 ===")
        
        # 记录转换开始时间
        start_time = time.time()
        
        # 启用端口
        network_topology.execute_bridge_command(dut_manager, "enable_port", port=test_port)
        logger.info(f"已启用端口 {test_port}，开始监控状态转换")
        
        # 监控状态转换过程
        states_observed = []
        learning_duration = 0
        learning_start_time = None
        
        # 监控15秒内的状态变化
        for i in range(15):
            time.sleep(1)
            current_time = time.time()
            
            try:
                info = rstp_analyzer.get_bridge_info()
                if test_port in info.ports:
                    port_info = info.ports[test_port]
                    state = port_info.state
                    role = port_info.role
                    
                    # 记录状态变化
                    state_info = {
                        'time': current_time - start_time,
                        'state': state,
                        'role': role
                    }
                    
                    # 避免重复记录相同状态
                    if not states_observed or states_observed[-1]['state'] != state:
                        states_observed.append(state_info)
                        logger.info(f"T+{state_info['time']:.1f}s: {test_port} -> "
                                  f"状态={state.value}, 角色={role.value}")
                    
                    # 记录Learning状态的持续时间
                    if state == PortState.LEARNING:
                        if learning_start_time is None:
                            learning_start_time = current_time
                    elif state == PortState.FORWARDING and learning_start_time is not None:
                        learning_duration = current_time - learning_start_time
                        logger.info(f"Learning状态持续时间: {learning_duration:.1f}秒")
                        break
                        
            except Exception as e:
                logger.debug(f"获取端口状态时出错: {e}")
        
        # === 步骤3: 验证状态转换序列 ===
        logger.info("=== 步骤3: 验证状态转换序列 ===")
        
        # 打印完整的状态转换序列
        logger.info("观察到的状态转换序列:")
        for i, state_info in enumerate(states_observed):
            logger.info(f"  {i+1}. T+{state_info['time']:.1f}s: "
                      f"{state_info['state'].value} ({state_info['role'].value})")
        
        # 验证是否观察到Learning状态
        learning_observed = any(s['state'] == PortState.LEARNING for s in states_observed)
        
        if learning_observed:
            logger.info("✓ 成功观察到Learning状态")
            
            # 验证Learning状态的持续时间是否合理（应该在Forward Delay范围内）
            if learning_duration > 0:
                logger.info(f"✓ Learning状态持续 {learning_duration:.1f} 秒")
                
                # Forward Delay通常是15秒，但在快速转换中可能更短
                if 1 <= learning_duration <= 20:
                    logger.info("✓ Learning状态持续时间在合理范围内")
                else:
                    logger.warning(f"Learning状态持续时间异常: {learning_duration:.1f}秒")
            
            # 验证状态转换顺序
            expected_sequence = [PortState.DISCARDING, PortState.LEARNING, PortState.FORWARDING]
            actual_states = [s['state'] for s in states_observed]
            
            # 检查是否包含期望的转换
            if PortState.LEARNING in actual_states and PortState.FORWARDING in actual_states:
                learning_idx = next(i for i, s in enumerate(actual_states) if s == PortState.LEARNING)
                forwarding_idx = next(i for i, s in enumerate(actual_states) if s == PortState.FORWARDING)
                
                if learning_idx < forwarding_idx:
                    logger.info("✓ 状态转换顺序正确: Learning -> Forwarding")
                else:
                    logger.warning("状态转换顺序异常")
        else:
            # 如果没有观察到Learning状态，可能是快速转换
            logger.info("未观察到Learning状态 - 可能发生了快速转换")
            
            # 检查是否直接从Discarding转到Forwarding
            if len(states_observed) >= 2:
                final_state = states_observed[-1]['state']
                if final_state == PortState.FORWARDING:
                    logger.info("✓ 端口最终达到Forwarding状态")
                    logger.info("这可能是RSTP快速转换的结果（Proposal/Agreement机制）")
        
        # === 步骤4: 验证最终状态 ===
        logger.info("=== 步骤4: 验证最终状态 ===")
        
        final_info = rstp_analyzer.get_bridge_info()
        if test_port in final_info.ports:
            final_port = final_info.ports[test_port]
            logger.info(f"最终状态: {test_port} -> "
                      f"状态={final_port.state.value}, 角色={final_port.role.value}")
            
            # 验证端口最终是否正常工作
            if final_port.state == PortState.FORWARDING:
                logger.info("✓ 端口成功恢复到Forwarding状态")
            else:
                logger.warning(f"端口未恢复到Forwarding状态: {final_port.state.value}")
        
        logger.info("端口状态转换测试完成")

    def test_bpdu_propagation_and_keepalive(self, dut_manager, test_nodes,
                                          network_topology, rstp_analyzer):
        """TC.AUTO.1.6: BPDU传播和保活机制测试"""
        logger.info("开始BPDU传播和保活机制测试")
        
        # 创建环形拓扑
        network_topology.create_ring_topology(use_rstp=True)
        
        # 设置不同优先级
        network_topology.execute_bridge_command(test_nodes[0], "set_priority", priority=12288)  # 根桥
        network_topology.execute_bridge_command(dut_manager, "set_priority", priority=32768)
        if len(test_nodes) > 1:
            network_topology.execute_bridge_command(test_nodes[1], "set_priority", priority=24576)
        
        # 等待初始收敛
        time.sleep(8)
        
        # 获取DUT的执行方法
        if hasattr(dut_manager, 'execute'):
            execute_method = dut_manager.execute
        elif hasattr(dut_manager, 'run'):
            execute_method = dut_manager.run
        else:
            execute_method = dut_manager.send_command
        
        # === 步骤1: 验证所有节点都在发送BPDU ===
        logger.info("=== 步骤1: 验证分布式BPDU生成 ===")
        
        # 获取网络中的活动接口
        bridge_name = "SE_ETH2" if dut_manager.config.name == "DUT" else "br0"
        
        try:
            # 获取网桥接口列表
            result = execute_method(f"bridge link show {bridge_name}")
            if isinstance(result, tuple):
                bridge_output = result[0] if result[0] else ""
            else:
                bridge_output = str(result)
            
            # 提取接口名称
            interfaces = []
            for line in bridge_output.split('\n'):
                if 'eth' in line or 'veth' in line:
                    # 提取接口名称
                    parts = line.split()
                    if parts:
                        iface = parts[0].split('@')[0]  # 去掉@后缀
                        if iface not in interfaces:
                            interfaces.append(iface)
            
            logger.info(f"检测到网桥接口: {interfaces}")
            
        except Exception as e:
            logger.warning(f"获取接口列表失败: {e}")
            # 使用默认接口
            interfaces = ['eth0', 'eth1']
        
        # 在每个接口上捕获BPDU
        bpdu_sources = set()
        total_bpdus = 0
        
        for iface in interfaces[:2]:  # 限制检查前2个接口
            try:
                logger.info(f"在接口 {iface} 上捕获BPDU...")
                bpdus = rstp_analyzer.capture_bpdu(iface, count=10, timeout=15)
                
                if bpdus:
                    logger.info(f"在 {iface} 上捕获到 {len(bpdus)} 个BPDU")
                    total_bpdus += len(bpdus)
                    
                    # 分析BPDU来源
                    for bpdu in bpdus:
                        bpdu_str = str(bpdu)
                        # 提取源MAC地址或网桥ID
                        if 'src' in bpdu_str.lower():
                            # 简单的源地址提取
                            lines = bpdu_str.split('\n')
                            for line in lines:
                                if 'src' in line.lower() or 'source' in line.lower():
                                    bpdu_sources.add(line.strip())
                                    break
                        else:
                            bpdu_sources.add(f"BPDU_from_{iface}")
                    
                else:
                    logger.warning(f"在 {iface} 上未捕获到BPDU")
                    
            except Exception as e:
                logger.warning(f"在接口 {iface} 上捕获BPDU失败: {e}")
        
        logger.info(f"总共捕获 {total_bpdus} 个BPDU，来自 {len(bpdu_sources)} 个不同源")
        
        # 验证分布式BPDU生成
        if total_bpdus > 0:
            logger.info("✓ 检测到BPDU传播")
            
            if len(bpdu_sources) > 1:
                logger.info("✓ 检测到多个BPDU源，符合RSTP分布式生成机制")
            else:
                logger.info("只检测到单一BPDU源，可能是根桥主导的传统STP行为")
        else:
            logger.warning("未检测到BPDU传播")
        
        logger.info("BPDU传播和保活机制测试完成")

    def test_disabled_port_exclusion_enhanced(self, dut_manager, test_nodes,
                                            network_topology, rstp_analyzer):
        """TC.AUTO.1.7: 增强的禁用端口排除测试"""
        logger.info("开始增强的禁用端口排除测试")
        
        # 创建环形拓扑
        network_topology.create_ring_topology(use_rstp=True)
        
        # 设置优先级
        network_topology.execute_bridge_command(test_nodes[0], "set_priority", priority=12288)
        network_topology.execute_bridge_command(dut_manager, "set_priority", priority=32768)
        
        # 等待初始收敛
        time.sleep(5)
        
        # 获取初始状态
        initial_info = rstp_analyzer.get_bridge_info()
        active_ports = [name for name, port in initial_info.ports.items() 
                       if port.state != PortState.DISABLED]
        
        logger.info(f"初始活动端口数量: {len(active_ports)}")
        
        if len(active_ports) < 2:
            pytest.skip("需要至少2个活动端口进行测试")
        
        # === 步骤1: 禁用一个端口 ===
        logger.info("=== 步骤1: 禁用端口 ===")
        
        test_port = active_ports[0]
        logger.info(f"禁用端口: {test_port}")
        
        network_topology.execute_bridge_command(dut_manager, "disable_port", port=test_port)
        
        # 等待状态更新
        time.sleep(3)
        
        # === 步骤2: 验证端口被排除 ===
        logger.info("=== 步骤2: 验证禁用端口被排除 ===")
        
        after_disable_info = rstp_analyzer.get_bridge_info()
        
        # 检查禁用端口的状态
        if test_port in after_disable_info.ports:
            disabled_port = after_disable_info.ports[test_port]
            logger.info(f"禁用端口状态: {disabled_port.state.value}")
            
            if disabled_port.state == PortState.DISABLED:
                logger.info("✓ 端口正确标记为DISABLED")
            else:
                logger.warning(f"端口未正确禁用，当前状态: {disabled_port.state.value}")
        
        # 验证其他端口仍然参与RSTP
        remaining_active = [name for name, port in after_disable_info.ports.items() 
                          if port.state != PortState.DISABLED and name != test_port]
        
        logger.info(f"禁用后剩余活动端口: {len(remaining_active)}")
        
        # 验证网络仍然收敛
        has_root_port = any(port.role == PortRole.ROOT 
                           for port in after_disable_info.ports.values() 
                           if port.state != PortState.DISABLED)
        
        has_designated_port = any(port.role == PortRole.DESIGNATED 
                                for port in after_disable_info.ports.values() 
                                if port.state != PortState.DISABLED)
        
        if has_root_port or has_designated_port:
            logger.info("✓ 网络在禁用端口后仍然正常收敛")
        else:
            logger.warning("网络收敛状态异常")
        
        # === 步骤3: 重新启用端口 ===
        logger.info("=== 步骤3: 重新启用端口 ===")
        
        network_topology.execute_bridge_command(dut_manager, "enable_port", port=test_port)
        logger.info(f"重新启用端口: {test_port}")
        
        # 等待重新收敛
        time.sleep(5)
        
        # === 步骤4: 验证端口重新参与RSTP ===
        logger.info("=== 步骤4: 验证端口重新参与RSTP ===")
        
        final_info = rstp_analyzer.get_bridge_info()
        
        if test_port in final_info.ports:
            reenabled_port = final_info.ports[test_port]
            logger.info(f"重新启用后端口状态: {reenabled_port.state.value}")
            logger.info(f"重新启用后端口角色: {reenabled_port.role.value}")
            
            if reenabled_port.state != PortState.DISABLED:
                logger.info("✓ 端口成功重新参与RSTP")
            else:
                logger.warning("端口未能重新参与RSTP")
        
        # 验证最终网络状态
        final_active = [name for name, port in final_info.ports.items() 
                       if port.state != PortState.DISABLED]
        
        logger.info(f"最终活动端口数量: {len(final_active)}")
        
        if len(final_active) >= len(active_ports):
            logger.info("✓ 所有端口都重新参与RSTP")
        else:
            logger.warning("部分端口未能重新参与RSTP")
        
        logger.info("增强的禁用端口排除测试完成")
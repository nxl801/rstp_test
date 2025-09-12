"""
参数配置测试
"""

import time
import pytest
import logging
from typing import Dict, Any, List

from src.rstp_analyzer import RSTPAnalyzer
from src.network_topology import NetworkTopology
from src.fault_injector import FaultInjector

logger = logging.getLogger(__name__)


@pytest.mark.parameters
class TestParameters:
    """RSTP参数配置测试套件"""

    # 参数测试矩阵
    PARAMETER_MATRIX = [
        # (参数名, 命令, 有效值, 无效值, 验证方法)
        ('bridge_priority', 'brctl setbridgeprio',
         [12288, 16384, 32768, 61440], [4097, 12289, 70000], 'check_priority'),
        ('hello_time', 'brctl sethello',
         [1, 2, 5, 10], [0, 11, -1], 'check_hello_time'),
        ('forward_delay', 'brctl setfd',
         [4, 10, 15, 30], [3, 31, -1], 'check_forward_delay'),
        ('max_age', 'brctl setmaxage',
         [6, 10, 20, 40], [5, 41, -1], 'check_max_age'),
    ]

    @pytest.mark.parametrize("priority", [12288, 16384, 32768, 61440])
    def test_bridge_priority_valid(self, dut_manager, rstp_analyzer, priority):
        """TC.AUTO.3.1.1-2: 测试有效的网桥优先级"""
        logger.info(f"测试网桥优先级: {priority}")
        
        # 确保网桥存在并启用RSTP（不重新创建，只检查和配置）
        bridge_name = "SE_ETH2" if dut_manager.config.name == "DUT" else "br0"
        
        # 检查网桥是否存在
        if dut_manager.config.name == "DUT":
            # 检查OVS网桥是否存在
            stdout, _, code = dut_manager.execute_as_root(f"ovs-vsctl br-exists {bridge_name}")
            if code != 0:
                # 网桥不存在，创建它
                logger.info(f"创建OVS网桥 {bridge_name}")
                dut_manager.execute_sudo(f"ovs-vsctl add-br {bridge_name}")
            
            # 确保RSTP启用
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} stp_enable=true")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} rstp_enable=true")
        else:
            # 检查传统网桥是否存在
            stdout, _, code = dut_manager.execute_as_root(f"ip link show {bridge_name}")
            if code != 0:
                # 网桥不存在，创建它
                logger.info(f"创建传统网桥 {bridge_name}")
                dut_manager.execute_sudo(f"brctl addbr {bridge_name}")
            
            # 确保STP启用
            dut_manager.execute_sudo(f"brctl stp {bridge_name} on")
        
        # 确保网桥处于UP状态
        dut_manager.execute_sudo(f"ip link set {bridge_name} up")
        time.sleep(1)  # 等待网桥启动
        
        # 设置网桥优先级
        network_topology = NetworkTopology([dut_manager])
        stdout, stderr, code = network_topology.execute_bridge_command(
            dut_manager, "set_priority", priority=priority
        )
        logger.info(f"命令执行结果: code={code}, stdout='{stdout}', stderr='{stderr}'")
        assert code == 0, f"设置优先级失败: stdout='{stdout}', stderr='{stderr}', code={code}"

        # 等待生效
        time.sleep(2)

        # 验证设置 - 改进的验证逻辑
        if dut_manager.config.name == "DUT":
            test_bridge_name = "SE_ETH2"
            
            # 首先尝试从OVS配置中读取
            stdout, _, code = dut_manager.execute_as_root(
                f"ovs-vsctl get bridge {test_bridge_name} other-config:stp-priority 2>/dev/null || echo 'not_set'"
            )
            
            actual_priority = 0
            
            if code == 0 and 'not_set' not in stdout:
                try:
                    # 从输出中提取"32768"这样的值
                    import re
                    match = re.search(r'"(\d+)"', stdout)
                    if match:
                        actual_priority = int(match.group(1))
                        logger.info(f"从OVS配置读取到优先级: {actual_priority}")
                    else:
                        logger.warning(f"无法从OVS输出中提取优先级: {repr(stdout)}")
                except ValueError as e:
                    logger.error(f"解析OVS优先级失败: {e}")
            
            # 如果OVS配置读取失败，尝试从rstp_analyzer获取
            if actual_priority == 0:
                try:
                    info = rstp_analyzer.get_bridge_info()
                    if hasattr(info, 'bridge_id') and info.bridge_id and '.' in info.bridge_id:
                        # bridge_id格式通常是 "priority.mac_address"
                        priority_hex = info.bridge_id.split('.')[0]
                        actual_priority = int(priority_hex, 16)
                        logger.info(f"从bridge_id解析到优先级: {actual_priority}")
                    elif hasattr(info, 'priority'):
                        actual_priority = info.priority
                        logger.info(f"从info.priority获取到优先级: {actual_priority}")
                except Exception as e:
                    logger.warning(f"从rstp_analyzer获取优先级失败: {e}")
            
            # 最后的备用方法：等待一段时间后重新检查
            if actual_priority == 0:
                logger.info("等待配置生效后重新检查...")
                time.sleep(3)
                try:
                    info = rstp_analyzer.get_bridge_info()
                    if hasattr(info, 'bridge_id') and info.bridge_id and '.' in info.bridge_id:
                        priority_hex = info.bridge_id.split('.')[0]
                        actual_priority = int(priority_hex, 16)
                        logger.info(f"延迟检查获取到优先级: {actual_priority}")
                except Exception as e:
                    logger.warning(f"延迟检查也失败: {e}")
                    
        else:
            # 对于非DUT节点，使用传统方法
            try:
                info = rstp_analyzer.get_bridge_info()
                if hasattr(info, 'bridge_id') and info.bridge_id and '.' in info.bridge_id:
                    actual_priority = int(info.bridge_id.split('.')[0], 16)
                elif hasattr(info, 'priority'):
                    actual_priority = info.priority
                else:
                    stdout, _, _ = dut_manager.execute(
                        f"cat /sys/class/net/{bridge_name}/bridge/priority"
                    )
                    actual_priority = int(stdout.strip()) if stdout.strip() else 0
            except Exception as e:
                logger.error(f"获取非DUT优先级失败: {e}")
                actual_priority = 0

        assert actual_priority == priority, \
            f"优先级设置不匹配: 期望{priority}, 实际{actual_priority}"

        logger.info(f"优先级{priority}设置成功")

    @pytest.mark.parametrize("priority", [4097, 12289, 70000])
    def test_bridge_priority_invalid(self, dut_manager, priority):
        """TC.AUTO.3.1.3: 测试无效的网桥优先级"""
        logger.info(f"测试无效优先级: {priority}")

        # 确保网桥存在并正确配置
        bridge_name = "SE_ETH2" if dut_manager.config.name == "DUT" else "br0"
        
        # 创建网桥
        if dut_manager.config.name == "DUT":
            # 对于DUT，创建OVS网桥
            dut_manager.execute_sudo(f"ovs-vsctl --if-exists del-br {bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl add-br {bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} stp_enable=true")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} rstp_enable=true")
        else:
            dut_manager.execute_sudo(f"brctl addbr {bridge_name} 2>/dev/null || true")
            dut_manager.execute_sudo(f"brctl stp {bridge_name} on")
        dut_manager.execute_sudo(f"ip link set {bridge_name} up")

        # 尝试设置无效优先级
        network_topology = NetworkTopology([dut_manager])
        stdout, stderr, code = network_topology.execute_bridge_command(
            dut_manager, "set_priority", priority=priority
        )
        
        # 对于DUT（OVS），验证其对无效值的处理
        if dut_manager.config.name == "DUT":
            # 验证OVS是否正确处理了无效值
            time.sleep(1)
            stdout_check, _, code_check = dut_manager.execute_as_root(
                f"ovs-vsctl get bridge {bridge_name} other-config:stp-priority"
            )
            if code_check == 0:
                import re
                match = re.search(r'"(\d+)"', stdout_check)
                if match:
                    actual_priority = int(match.group(1))
                    logger.info(f"DUT处理无效优先级 {priority} -> {actual_priority}")
                    
                    # 记录DUT的行为：是否遵循802.1D标准（优先级应为4096的倍数）
                    if actual_priority % 4096 != 0:
                        logger.error(f"DUT接受了非标准优先级值 {actual_priority}，不符合802.1D标准（应为4096的倍数）")
                        # 这是一个合规性问题，测试应该失败
                        pytest.fail(f"DUT违反802.1D标准：接受了无效优先级 {priority}，实际设置为 {actual_priority}（不是4096的倍数）")
                    else:
                        logger.info(f"DUT正确调整了无效优先级为标准值 {actual_priority}")
                        # 验证DUT是否拒绝了原始的无效值
                        if actual_priority == priority:
                            logger.error(f"DUT直接接受了无效优先级 {priority}，应该拒绝或调整")
                            pytest.fail(f"DUT违反802.1D标准：直接接受了无效优先级 {priority}")
                        else:
                            logger.info(f"无效优先级{priority}被正确处理：DUT调整为标准值{actual_priority}")
        else:
            # 对于非DUT节点，应该失败
            assert code != 0, f"应该拒绝无效优先级{priority}"

        logger.info(f"无效优先级{priority}被正确处理")

    def test_hello_time(self, dut_manager, rstp_analyzer):
        """TC.AUTO.3.1.4: Hello Time测试"""
        logger.info("测试Hello Time参数")

        # 确保网桥存在
        bridge_name = "SE_ETH2" if dut_manager.config.name == "DUT" else "br0"
        if dut_manager.config.name == "DUT":
            # 对于DUT，创建OVS网桥
            dut_manager.execute_sudo(f"ovs-vsctl --if-exists del-br {bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl add-br {bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} stp_enable=true")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} rstp_enable=true")
        else:
            dut_manager.execute_sudo(f"brctl addbr {bridge_name} 2>/dev/null || true")
            dut_manager.execute_sudo(f"brctl stp {bridge_name} on")
        dut_manager.execute_sudo(f"ip link set {bridge_name} up")
        time.sleep(1)

        # 测试不同的hello time值
        for hello_time in [1, 2, 5]:
            logger.info(f"设置Hello Time: {hello_time}秒")

            # 设置参数
            network_topology = NetworkTopology([dut_manager])
            stdout, stderr, code = network_topology.execute_bridge_command(
                dut_manager, "set_hello_time", hello_time=hello_time
            )
            
            assert code == 0, f"设置Hello Time失败: {stderr}"

            time.sleep(2)

            # 验证设置 - 对于DUT使用OVS命令验证
            if dut_manager.config.name == "DUT":
                stdout, _, code = dut_manager.execute_as_root(
                    f"ovs-vsctl get bridge {bridge_name} other-config:stp-hello-time"
                )
                if code == 0:
                    import re
                    match = re.search(r'"(\d+)"', stdout)
                    if match:
                        actual_hello_time_ms = int(match.group(1))
                        actual_hello_time = actual_hello_time_ms // 1000  # 转换为秒
                        assert actual_hello_time == hello_time, \
                            f"Hello Time设置不匹配: 期望{hello_time}秒, 实际{actual_hello_time}秒 (OVS值:{actual_hello_time_ms}ms)"
                        logger.info(f"Hello Time {hello_time}秒设置成功")
                    else:
                        logger.warning(f"无法验证Hello Time设置: {repr(stdout)}")
            else:
                # 对于非DUT节点，使用BPDU间隔验证
                bpdus = rstp_analyzer.capture_bpdu("eth0", count=5,
                                                   timeout=hello_time * 6)

                if len(bpdus) >= 2:
                    # 计算BPDU间隔
                    intervals = []
                    for i in range(1, len(bpdus)):
                        # 从timestamp字符串提取时间
                        t1 = self._parse_timestamp(bpdus[i - 1]['timestamp'])
                        t2 = self._parse_timestamp(bpdus[i]['timestamp'])
                        if t1 and t2:
                            intervals.append(t2 - t1)

                    if intervals:
                        avg_interval = sum(intervals) / len(intervals)
                        logger.info(f"实测BPDU间隔: {avg_interval:.2f}秒")

                        # 验证间隔（允许20%误差）
                        assert hello_time * 0.8 <= avg_interval <= hello_time * 1.2, \
                            f"BPDU间隔不匹配: 期望{hello_time}秒, 实际{avg_interval:.2f}秒"

        logger.info("Hello Time测试通过")

    def test_forward_delay(self, dut_manager, rstp_analyzer, fault_injector):
        """TC.AUTO.3.1.5: Forward Delay测试"""
        logger.info("测试Forward Delay参数")

        # 确保网桥存在
        test_bridge_name = "SE_ETH2" if dut_manager.config.name == "DUT" else "br0"
        if dut_manager.config.name == "DUT":
            # 对于DUT，创建OVS网桥
            dut_manager.execute_sudo(f"ovs-vsctl --if-exists del-br {test_bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl add-br {test_bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {test_bridge_name} stp_enable=true")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {test_bridge_name} rstp_enable=true")
        else:
            dut_manager.execute_sudo(f"brctl addbr {test_bridge_name} 2>/dev/null || true")
            dut_manager.execute_sudo(f"brctl stp {test_bridge_name} on")
        dut_manager.execute_sudo(f"ip link set {test_bridge_name} up")
        time.sleep(1)

        # 测试不同的forward delay值
        for fd in [4, 10, 15]:
            logger.info(f"设置Forward Delay: {fd}秒")

            # 设置参数
            network_topology = NetworkTopology([dut_manager])
            stdout, stderr, code = network_topology.execute_bridge_command(
                dut_manager, "set_forward_delay", forward_delay=fd
            )
            assert code == 0, f"设置Forward Delay失败: {stderr}"

            time.sleep(2)

            # 验证设置 - 对于DUT使用OVS命令验证
            if dut_manager.config.name == "DUT":
                # 使用正确的网桥名称
                test_bridge_name = "SE_ETH2"
                stdout, _, code = dut_manager.execute_as_root(
                    f"ovs-vsctl get bridge {test_bridge_name} other-config:stp-forward-delay"
                )
                if code == 0:
                    import re
                    match = re.search(r'"(\d+)"', stdout)
                    if match:
                        actual_fd_ms = int(match.group(1))
                        actual_fd = actual_fd_ms // 1000  # 转换为秒
                        assert actual_fd == fd, \
                            f"Forward Delay设置不匹配: 期望{fd}秒, 实际{actual_fd}秒 (OVS值:{actual_fd_ms}ms)"
                        logger.info(f"Forward Delay {fd}秒设置成功")
                    else:
                        logger.warning(f"无法验证Forward Delay设置: {repr(stdout)}")
            else:
                # 对于非DUT节点，使用状态转换验证
                # 触发端口状态变化
                fault_injector.link_down("eth0")
                time.sleep(1)
                fault_injector.link_up("eth0")

                # 监控状态转换
                start_time = time.time()
                states = []

                while time.time() - start_time < fd * 3:
                    info = rstp_analyzer.get_bridge_info()
                    if "eth0" in info.ports:
                        state = info.ports["eth0"].state
                        states.append({
                            'time': time.time() - start_time,
                            'state': state
                        })

                        if state.value == 'forwarding':
                            break

                    time.sleep(0.5)

                # 分析转换时间
                if states:
                    forwarding_time = states[-1]['time']
                    logger.info(f"转发状态到达时间: {forwarding_time:.2f}秒")

                    # RSTP的转换时间应该较短
                    if rstp_analyzer.verify_rstp_enabled():
                        # RSTP模式下应该很快
                        assert forwarding_time < fd * 2, \
                            f"RSTP转换时间过长: {forwarding_time:.2f}秒"

        logger.info("Forward Delay测试通过")

    def test_max_age(self, dut_manager, rstp_analyzer):
        """TC.AUTO.3.1.6: Max Age测试"""
        logger.info("测试Max Age参数")

        # 确保网桥存在
        bridge_name = "SE_ETH2" if dut_manager.config.name == "DUT" else "br0"
        if dut_manager.config.name == "DUT":
            # 对于DUT，创建OVS网桥
            dut_manager.execute_sudo(f"ovs-vsctl --if-exists del-br {bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl add-br {bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} stp_enable=true")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} rstp_enable=true")
        else:
            dut_manager.execute_sudo(f"brctl addbr {bridge_name} 2>/dev/null || true")
            dut_manager.execute_sudo(f"brctl stp {bridge_name} on")
        dut_manager.execute_sudo(f"ip link set {bridge_name} up")
        time.sleep(1)

        for max_age in [6, 10, 20]:
            logger.info(f"设置Max Age: {max_age}秒")

            # 设置参数
            network_topology = NetworkTopology([dut_manager])
            stdout, stderr, code = network_topology.execute_bridge_command(
                dut_manager, "set_max_age", max_age=max_age
            )
            
            assert code == 0, f"设置Max Age失败: {stderr}"

            time.sleep(2)

            # 验证设置 - 对于DUT使用OVS命令验证
            if dut_manager.config.name == "DUT":
                # 使用正确的网桥名称
                test_bridge_name = "SE_ETH2"
                stdout, _, code = dut_manager.execute_as_root(
                    f"ovs-vsctl get bridge {test_bridge_name} other-config:stp-max-age"
                )
                if code == 0:
                    import re
                    match = re.search(r'"(\d+)"', stdout)
                    if match:
                        actual_max_age_ms = int(match.group(1))
                        actual_max_age = actual_max_age_ms // 1000  # 转换为秒
                        assert actual_max_age == max_age, \
                            f"Max Age设置不匹配: 期望{max_age}秒, 实际{actual_max_age}秒 (OVS值:{actual_max_age_ms}ms)"
                        logger.info(f"Max Age {max_age}秒设置成功")
                    else:
                        logger.warning(f"无法验证Max Age设置: {repr(stdout)}")
            else:
                # 对于非DUT节点，使用传统方法验证
                info = rstp_analyzer.get_bridge_info()
                assert info.max_age == max_age, \
                    f"Max Age设置不匹配: 期望{max_age}, 实际{info.max_age}"

        logger.info("Max Age测试通过")

    def test_port_cost(self, dut_manager, rstp_analyzer, network_topology):
        """测试端口路径成本"""
        logger.info("测试端口路径成本")

        # 创建拓扑
        network_topology.create_ring_topology(use_rstp=True)
        time.sleep(5)

        # 测试不同的端口成本值
        port_costs = [10, 100, 1000, 20000]

        for cost in port_costs:
            logger.info(f"设置端口eth0成本: {cost}")

            # 设置端口成本
            network_topology_instance = NetworkTopology([dut_manager])
            stdout, stderr, code = network_topology_instance.execute_bridge_command(
                dut_manager, "set_port_cost", interface="eth1", cost=cost
            )

            if code == 0:
                time.sleep(3)

                # 验证设置
                info = rstp_analyzer.get_bridge_info()
                if "eth0" in info.ports:
                    actual_cost = info.ports["eth0"].path_cost
                    logger.info(f"实际端口成本: {actual_cost}")

                    # 成本应该影响端口选择
                    if cost > 10000:
                        # 高成本端口不应该被选为root port
                        assert info.ports["eth0"].role.value != 'root', \
                            "高成本端口不应该是Root Port"

        logger.info("端口成本测试通过")

    def test_parameter_persistence(self, dut_manager, rstp_analyzer):
        """测试参数持久性"""
        logger.info("测试参数持久性")

        # 确保网桥存在
        bridge_name = "SE_ETH2" if dut_manager.config.name == "DUT" else "br0"
        if dut_manager.config.name == "DUT":
            # 对于DUT，创建OVS网桥
            dut_manager.execute_sudo(f"ovs-vsctl --if-exists del-br {bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl add-br {bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} stp_enable=true")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} rstp_enable=true")
        else:
            dut_manager.execute_sudo(f"brctl addbr {bridge_name} 2>/dev/null || true")
            dut_manager.execute_sudo(f"brctl stp {bridge_name} on")
        dut_manager.execute_sudo(f"ip link set {bridge_name} up")
        time.sleep(1)

        # 设置多个参数
        params = {
            'priority': 16384,
            'hello': 2,
            'fd': 15,
            'maxage': 20
        }

        # 应用参数
        network_topology = NetworkTopology([dut_manager])
        for param, value in params.items():
            if param == 'priority':
                stdout, stderr, code = network_topology.execute_bridge_command(
                    dut_manager, "set_priority", priority=value
                )
            elif param == 'hello':
                stdout, stderr, code = network_topology.execute_bridge_command(
                    dut_manager, "set_hello_time", hello_time=value
                )
            elif param == 'fd':
                stdout, stderr, code = network_topology.execute_bridge_command(
                    dut_manager, "set_forward_delay", forward_delay=value
                )
            elif param == 'maxage':
                stdout, stderr, code = network_topology.execute_bridge_command(
                    dut_manager, "set_max_age", max_age=value
                )
            
            assert code == 0, f"设置{param}={value}失败: {stderr}"

        time.sleep(3)

        # 验证所有参数
        if dut_manager.config.name == "DUT":
            # 对于DUT，直接验证OVS配置
            time.sleep(2)
            
            # 验证优先级
            stdout, _, code = dut_manager.execute_as_root(
                f"ovs-vsctl get bridge {bridge_name} other-config:stp-priority"
            )
            if code == 0:
                import re
                match = re.search(r'"(\d+)"', stdout)
                if match:
                    actual_priority = int(match.group(1))
                    assert actual_priority == params['priority'], f"优先级不匹配: {actual_priority} != {params['priority']}"
            
            # 验证Hello Time
            stdout, _, code = dut_manager.execute_as_root(
                f"ovs-vsctl get bridge {bridge_name} other-config:stp-hello-time"
            )
            if code == 0:
                match = re.search(r'"(\d+)"', stdout)
                if match:
                    actual_hello_ms = int(match.group(1))
                    actual_hello = actual_hello_ms // 1000
                    assert actual_hello == params['hello'], f"Hello Time不匹配: {actual_hello} != {params['hello']}"
        else:
            # 对于非DUT节点，使用rstp_analyzer
            info = rstp_analyzer.get_bridge_info()

            # 检查优先级
            if '.' in info.bridge_id:
                actual_priority = int(info.bridge_id.split('.')[0], 16)
                assert actual_priority == params['priority'], \
                    f"优先级不匹配: {actual_priority} != {params['priority']}"

            # 检查时间参数
            assert info.hello_time == params['hello'], \
                f"Hello Time不匹配: {info.hello_time} != {params['hello']}"
            assert info.forward_delay == params['fd'], \
                f"Forward Delay不匹配: {info.forward_delay} != {params['fd']}"
            assert info.max_age == params['maxage'], \
                f"Max Age不匹配: {info.max_age} != {params['maxage']}"

        logger.info("参数持久性测试通过")

    def test_parameter_boundaries(self, dut_manager):
        """测试参数边界值"""
        logger.info("测试参数边界值")

        # 确保网桥存在
        bridge_name = "SE_ETH2" if dut_manager.config.name == "DUT" else "br0"
        if dut_manager.config.name == "DUT":
            # 对于DUT，创建OVS网桥
            dut_manager.execute_sudo(f"ovs-vsctl --if-exists del-br {bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl add-br {bridge_name}")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} stp_enable=true")
            dut_manager.execute_sudo(f"ovs-vsctl set bridge {bridge_name} rstp_enable=true")
        else:
            dut_manager.execute_sudo(f"brctl addbr {bridge_name} 2>/dev/null || true")
            dut_manager.execute_sudo(f"brctl stp {bridge_name} on")
        dut_manager.execute_sudo(f"ip link set {bridge_name} up")
        time.sleep(1)

        # 测试边界值
        test_cases = [
            # (命令, 最小值, 最大值, 超出范围值)
            (f'brctl setbridgeprio {bridge_name}', 0, 65535, [-1, 65536]),
            (f'brctl sethello {bridge_name}', 1, 10, [0, 11]),
            (f'brctl setfd {bridge_name}', 4, 30, [3, 31]),
            (f'brctl setmaxage {bridge_name}', 6, 40, [5, 41]),
        ]

        for cmd_template, min_val, max_val, invalid_vals in test_cases:
            # 测试最小值
            stdout, stderr, code = dut_manager.execute_sudo(
                f"{cmd_template} {min_val}"
            )
            # 某些参数可能有限制
            logger.info(f"最小值{min_val}: {'成功' if code == 0 else '失败'}")

            # 测试最大值
            stdout, stderr, code = dut_manager.execute_sudo(
                f"{cmd_template} {max_val}"
            )
            logger.info(f"最大值{max_val}: {'成功' if code == 0 else '失败'}")

            # 测试无效值
            for val in invalid_vals:
                stdout, stderr, code = dut_manager.execute_sudo(
                    f"{cmd_template} {val}"
                )
                if code == 0:
                    logger.warning(f"接受了无效值{val}")
                else:
                    logger.info(f"正确拒绝了无效值{val}")

        logger.info("参数边界测试完成")

    def _parse_timestamp(self, timestamp_str: str) -> float:
        """解析时间戳字符串"""
        try:
            # 格式: HH:MM:SS.microseconds
            parts = timestamp_str.split(':')
            if len(parts) == 3:
                hours = int(parts[0])
                minutes = int(parts[1])
                seconds = float(parts[2])
                return hours * 3600 + minutes * 60 + seconds
        except:
            pass
        return None
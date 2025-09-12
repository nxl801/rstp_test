"""
网络拓扑管理模块
"""

import time
import logging
from typing import List, Dict, Optional
from enum import Enum

try:
    from .ssh_manager import SSHManager
except ImportError:
    from ssh_manager import SSHManager


class TopologyType(Enum):
    """拓扑类型枚举"""
    RING = "ring"
    STAR = "star"
    LINEAR = "linear"


class RSTPMethod(Enum):
    """RSTP配置方法"""
    MSTPD = "mstpd"
    IPROUTE2 = "iproute2"
    LEGACY = "legacy"
    OVS = "ovs"


class NetworkTopology:
    """网络拓扑管理器"""

    def __init__(self, nodes: List[SSHManager]):
        self.nodes = nodes
        self.logger = logging.getLogger("NetworkTopology")
        self.rstp_methods: Dict[str, RSTPMethod] = {}
        
        # 自动检测所有节点的RSTP支持方法
        for node in nodes:
            try:
                self.detect_rstp_support(node)
            except Exception as e:
                self.logger.error(f"检测节点 {node.config.name} 的RSTP支持失败: {e}")
    
    def execute_bridge_command(self, node: SSHManager, command_type: str, bridge: str = "br0", **kwargs):
        """根据节点类型和RSTP方法执行相应的网桥命令"""
        # 对于DUT，使用SE_ETH2作为网桥名称避免与Docker的br0冲突
        if node.config.name == "DUT" and bridge == "br0":
            bridge = "SE_ETH2"
        # 创建logger实例用于记录
        import logging
        logger = logging.getLogger(f"NetworkTopology_{node.config.name}")
        
        # 获取节点的RSTP方法
        method = self.rstp_methods.get(node.config.name, RSTPMethod.LEGACY)
        
        if command_type == "set_priority":
            priority = kwargs.get('priority', 32768)
            logger.info(f"{node.config.name}: 设置网桥优先级 {bridge} = {priority} (方法: {method.value})")
            
            if method == RSTPMethod.OVS:
                # 使用OVS标准方法设置优先级
                logger.info(f"{node.config.name}: 执行OVS设置优先级命令")
                result = node.execute_as_root(f"ovs-vsctl set bridge {bridge} other-config:stp-priority={priority}")
                logger.info(f"{node.config.name}: OVS设置优先级结果: {result}")
                # 同时设置RSTP优先级以确保兼容性
                node.execute_as_root(f"ovs-vsctl set bridge {bridge} other-config:rstp-priority={priority}")
                return result
            elif method == RSTPMethod.IPROUTE2:
                # 使用iproute2方法设置优先级
                logger.info(f"{node.config.name}: 执行iproute2设置优先级命令")
                result = node.execute_sudo(f"ip link set {bridge} type bridge priority {priority}")
                logger.info(f"{node.config.name}: iproute2设置优先级结果: {result}")
                return result
            elif method == RSTPMethod.MSTPD:
                # 使用mstpd方法设置优先级 - 新版本mstpd使用settreeprio命令
                # mstpd的优先级范围是0-15，需要将标准STP优先级转换
                mstpd_priority = priority // 4096  # 将标准优先级转换为0-15范围
                # 添加边界检查，确保优先级在有效范围内
                if mstpd_priority > 15:
                    mstpd_priority = 15
                    logger.warning(f"{node.config.name}: 优先级{priority}转换后超出范围，限制为15")
                elif mstpd_priority < 0:
                    mstpd_priority = 0
                    logger.warning(f"{node.config.name}: 优先级{priority}转换后小于0，设置为0")
                logger.info(f"{node.config.name}: 执行mstpd设置优先级命令 (标准优先级{priority} -> mstpd优先级{mstpd_priority})")
                result = node.execute_sudo(f"mstpctl settreeprio {bridge} 0 {mstpd_priority}")
                logger.info(f"{node.config.name}: mstpd设置优先级结果: {result}")
                return result
            else:
                # 使用传统brctl方法设置优先级
                logger.info(f"{node.config.name}: 执行brctl设置优先级命令")
                result = node.execute_sudo(f"brctl setbridgeprio {bridge} {priority}")
                logger.info(f"{node.config.name}: brctl设置优先级结果: {result}")
                return result
        elif command_type == "set_hello_time":
            hello_time = kwargs.get('hello_time', 2)
            if method == RSTPMethod.OVS:
                # OVS中hello time单位是毫秒
                hello_time_ms = hello_time * 1000
                return node.execute_as_root(f"ovs-vsctl set bridge {bridge} other-config:rstp-hello-time={hello_time_ms}")
            elif method == RSTPMethod.IPROUTE2:
                # iproute2中hello time单位是厘秒（1/100秒）
                hello_time_cs = hello_time * 100
                return node.execute_sudo(f"ip link set {bridge} type bridge hello_time {hello_time_cs}")
            elif method == RSTPMethod.MSTPD:
                return node.execute_sudo(f"mstpctl sethello {bridge} {hello_time}")
            else:
                return node.execute_sudo(f"brctl sethello {bridge} {hello_time}")
        elif command_type == "set_forward_delay":
            fd = kwargs.get('forward_delay', 15)
            if method == RSTPMethod.OVS:
                # OVS中forward delay单位是毫秒
                fd_ms = fd * 1000
                return node.execute_as_root(f"ovs-vsctl set bridge {bridge} other-config:rstp-forward-delay={fd_ms}")
            elif method == RSTPMethod.IPROUTE2:
                # iproute2中forward delay单位是厘秒（1/100秒）
                fd_cs = fd * 100
                return node.execute_sudo(f"ip link set {bridge} type bridge forward_delay {fd_cs}")
            elif method == RSTPMethod.MSTPD:
                return node.execute_sudo(f"mstpctl setfd {bridge} {fd}")
            else:
                return node.execute_sudo(f"brctl setfd {bridge} {fd}")
        elif command_type == "set_max_age":
            max_age = kwargs.get('max_age', 20)
            if method == RSTPMethod.OVS:
                # OVS中max age单位是毫秒
                max_age_ms = max_age * 1000
                return node.execute_as_root(f"ovs-vsctl set bridge {bridge} other-config:rstp-max-age={max_age_ms}")
            elif method == RSTPMethod.IPROUTE2:
                # iproute2中max age单位是厘秒（1/100秒）
                max_age_cs = max_age * 100
                return node.execute_sudo(f"ip link set {bridge} type bridge max_age {max_age_cs}")
            elif method == RSTPMethod.MSTPD:
                return node.execute_sudo(f"mstpctl setmaxage {bridge} {max_age}")
            else:
                return node.execute_sudo(f"brctl setmaxage {bridge} {max_age}")
        elif command_type == "set_port_cost":
            interface = kwargs.get('interface', 'eth1')
            cost = kwargs.get('cost', 20000)
            return node.execute_sudo(f"brctl setpathcost {bridge} {interface} {cost}")
        elif command_type == "disable_port":
            port = kwargs.get('port', 'eth0')
            # 使用故障注入器来禁用端口，确保逻辑状态同步
            try:
                from .fault_injector import FaultInjector
            except ImportError:
                from fault_injector import FaultInjector
            fault_injector = FaultInjector(node)
            fault_injector.link_down(port)
            return "", "", 0
        elif command_type == "enable_port":
            port = kwargs.get('port', 'eth0')
            # 使用故障注入器来启用端口，确保逻辑状态同步
            try:
                from .fault_injector import FaultInjector
            except ImportError:
                from fault_injector import FaultInjector
            fault_injector = FaultInjector(node)
            fault_injector.link_up(port)
            return "", "", 0
        
        return "", f"Unsupported command type: {command_type}", 1

    def detect_rstp_support(self, node: SSHManager) -> RSTPMethod:
        """检测RSTP支持方法"""
        if node.config.name in self.rstp_methods:
            cached_method = self.rstp_methods[node.config.name]
            self.logger.info(f"{node.config.name}: 使用缓存的RSTP方法: {cached_method.value}")
            return cached_method

        self.logger.info(f"{node.config.name}: 开始检测RSTP支持方法...")

        # DUT设备直接使用OVS方法，不检测mstpd
        if node.config.name == "DUT":
            self.logger.info(f"{node.config.name}: DUT设备，直接使用OVS方法")
            method = RSTPMethod.OVS
            self.rstp_methods[node.config.name] = method
            return method

        # 检测顺序：mstpd > iproute2 > legacy
        methods_to_check = [
            (RSTPMethod.MSTPD, self._check_mstpd_support),
            (RSTPMethod.IPROUTE2, self._check_iproute2_support),
            (RSTPMethod.LEGACY, self._check_legacy_support)
        ]
        
        for method, check_func in methods_to_check:
            if check_func(node):
                self.logger.info(f"{node.config.name}: 最终选择RSTP方法: {method.value}")
                self.rstp_methods[node.config.name] = method
                return method
        
        # 如果都不支持，抛出异常
        raise RuntimeError(f"{node.config.name}: 未找到支持的RSTP方法")

    def _check_mstpd_support(self, node: SSHManager) -> bool:
        """检查mstpd支持"""
        self.logger.info(f"{node.config.name}: 检查mstpd支持...")
        try:
            stdout, _, code = node.execute("which mstpd")
            self.logger.info(f"{node.config.name}: mstpd检查结果: code={code}")
            if code == 0:
                self.logger.info(f"{node.config.name}: 检查mstpd服务状态...")
                stdout, _, code = node.execute("sudo systemctl is-active mstpd")
                self.logger.info(f"{node.config.name}: mstpd服务状态: code={code}, output={stdout.strip()}")
                if code == 0 or "active" in stdout:
                    self.logger.info(f"{node.config.name}: 检测到mstpd支持")
                    return True
                else:
                    # 尝试启动mstpd
                    self.logger.info(f"{node.config.name}: 尝试启动mstpd服务...")
                    try:
                        node.execute_sudo("systemctl start mstpd", timeout=10)
                        time.sleep(2)
                        stdout, _, code = node.execute("sudo systemctl is-active mstpd", timeout=5)
                        self.logger.info(f"{node.config.name}: mstpd启动后状态: code={code}")
                        if code == 0:
                            return True
                        else:
                            self.logger.info(f"{node.config.name}: mstpd启动失败，可能服务不存在或权限不足")
                            return False
                    except Exception as e:
                        self.logger.error(f"{node.config.name}: mstpd启动异常: {e}")
                        return False
            else:
                self.logger.info(f"{node.config.name}: mstpd命令不存在")
                return False
        except Exception as e:
            self.logger.error(f"{node.config.name}: mstpd检测异常: {e}")
            return False

    def _check_iproute2_support(self, node: SSHManager) -> bool:
        """检查iproute2支持"""
        self.logger.info(f"{node.config.name}: 检查iproute2支持...")
        try:
            stdout, _, code = node.execute("ip -V")
            self.logger.info(f"{node.config.name}: ip命令检查: code={code}")
            if code == 0 and "iproute2" in stdout:
                self.logger.info(f"{node.config.name}: 检测到iproute2支持")
                return True
            else:
                self.logger.warning(f"{node.config.name}: iproute2不可用")
                return False
        except Exception as e:
            self.logger.error(f"{node.config.name}: iproute2检测异常: {e}")
            return False

    def _check_legacy_support(self, node: SSHManager) -> bool:
        """检查传统brctl支持"""
        self.logger.info(f"{node.config.name}: 检查传统brctl支持...")
        try:
            stdout, _, code = node.execute("which brctl")
            if code == 0:
                self.logger.info(f"{node.config.name}: 检测到brctl支持（传统STP）")
                return True
            else:
                self.logger.error(f"{node.config.name}: brctl命令不存在")
                return False
        except Exception as e:
            self.logger.error(f"{node.config.name}: brctl检测异常: {e}")
            return False

    def configure_bridge_rstp(self, node: SSHManager, bridge: str = "br0",
                            priority: int = 32768, interfaces: List[str] = None):
        # 对于DUT，使用SE_ETH2作为网桥名称避免与Docker的br0冲突
        if node.config.name == "DUT" and bridge == "br0":
            bridge = "SE_ETH2"

        """配置RSTP网桥"""
        self.logger.info(f"开始为 {node.config.name} 检测RSTP支持方法...")
        method = self.detect_rstp_support(node)
        self.logger.info(f"{node.config.name} 使用方法: {method.value}")

        # 清理旧配置
        if node.config.name == "DUT":
            # DUT只清理veth接口，不删除SE_ETH2网桥
            self.logger.info(f"清理 {node.config.name} 的测试接口...")
            self._cleanup_dut_interfaces(node, bridge)
        else:
            # 其他节点正常清理网桥
            self.logger.info(f"清理 {node.config.name} 的旧网桥配置...")
            self._cleanup_bridge(node, bridge)

        # 根据方法配置RSTP
        self.logger.info(f"为 {node.config.name} 配置RSTP ({method.value})...")
        if node.config.name == "DUT":
            # DUT只使用OVS配置，不使用mstpd
            self._configure_rstp_ovs(node, bridge, priority)
        elif method == RSTPMethod.MSTPD:
            self._configure_rstp_mstpd(node, bridge, priority)
        elif method == RSTPMethod.IPROUTE2:
            self._configure_rstp_iproute2(node, bridge, priority)
        elif method == RSTPMethod.OVS:
            self._configure_rstp_ovs(node, bridge, priority)
        else:
            self._configure_rstp_legacy(node, bridge, priority)
        self.logger.info(f"{node.config.name} RSTP核心配置完成")

        # **关键步骤：添加接口，保证mstpd正常工作**
        # DUT不需要mstpd相关逻辑，只有TestNode需要
        if method == RSTPMethod.MSTPD and node.config.name != "DUT":
            if not interfaces:
                # 如果没有接口，自动创建一个dummy0保证mstpd工作
                self.logger.warning(f"{node.config.name}: 未提供接口，自动创建 dummy0 占位")
                node.execute_sudo("ip link add dummy0 type dummy || true")
                node.execute_sudo("ip link set dummy0 up")
                node.execute_sudo(f"brctl addif {bridge} dummy0")

        # 添加接口（如果调用时有指定）
        if interfaces:
            self.logger.info(f"为 {node.config.name} 准备添加接口: {interfaces}")
            for iface in interfaces:
                self.logger.info(f"添加接口 {iface} 到 {node.config.name} 的网桥")
                self._add_interface_to_bridge(node, bridge, iface, method)
            self.logger.info(f"{node.config.name} 接口添加完成")

        # 对于非MSTPD方法，需要启动网桥（MSTPD方法已在配置时启动）
        # DUT的SE_ETH2网桥应该已经存在并运行，不需要额外启动
        if method != RSTPMethod.MSTPD and node.config.name != "DUT":
            self.logger.info(f"启动 {node.config.name} 的网桥 {bridge}...")
            node.execute_sudo(f"ip link set dev {bridge} up")

        # 验证配置
        self.logger.info(f"验证 {node.config.name} 的RSTP配置...")
        self._verify_rstp_enabled(node, bridge)
        self.logger.info(f"{node.config.name} 网桥配置验证完成")

    def _cleanup_dut_interfaces(self, node: SSHManager, bridge: str):
        """清理DUT的测试配置，保留SE_ETH2网桥和物理接口"""
        self.logger.info(f"重置DUT网桥 {bridge} 的RSTP配置...")
        
        # 重置网桥的RSTP配置到默认状态
        reset_commands = [
            f"ovs-vsctl set bridge {bridge} rstp_enable=false",
            f"ovs-vsctl remove bridge {bridge} other_config rstp-priority",
            f"ovs-vsctl remove bridge {bridge} other_config rstp-hello-time", 
            f"ovs-vsctl remove bridge {bridge} other_config rstp-forward-delay",
            f"ovs-vsctl remove bridge {bridge} other_config rstp-max-age"
        ]
        
        for cmd in reset_commands:
            node.execute_sudo(f"{cmd} 2>/dev/null || true")
        
        self.logger.info(f"DUT网桥 {bridge} 配置重置完成")

    def _cleanup_bridge(self, node: SSHManager, bridge: str):
        """清理网桥配置"""
        # 传统清理方法
        commands = [
            f"ip link set dev {bridge} down",
            f"ip link delete {bridge}",
            f"brctl delbr {bridge}"
        ]
        for cmd in commands:
            node.execute_sudo(f"{cmd} 2>/dev/null || true")

    def _configure_rstp_mstpd(self, node: SSHManager, bridge: str, priority: int):
        """使用mstpd配置RSTP"""
        # 第一步：创建桥并立即启用STP
        bridge_setup_commands = [
            f"brctl addbr {bridge}",
            f"brctl stp {bridge} on",   # 关键：立即打开 STP，否则 mstpd 不会接管
            f"ip link set dev {bridge} up",  # 启动桥，确保mstpd可以接管
        ]
        
        # 执行桥创建和启用
        for cmd in bridge_setup_commands:
            stdout, stderr, code = node.execute_sudo(cmd)
            if code != 0 and "exists" not in stderr:
                self.logger.warning(f"桥设置命令警告: {cmd}\n{stderr}")
        
        # 等待桥启动完成
        time.sleep(1)
        
        # 第二步：配置mstpd参数
        mstpd_commands = [
            f"mstpctl setforcevers {bridge} rstp",
            f"mstpctl setbridgeprio {bridge} {priority}",
            f"mstpctl setbridgehello {bridge} 2",
            f"mstpctl setbridgefdelay {bridge} 15",
            f"mstpctl setbridgemaxage {bridge} 20",
            f"mstpctl settxholdcount {bridge} 6",
        ]

        # 执行mstpd配置命令
        failed_commands = []
        for cmd in mstpd_commands:
            stdout, stderr, code = node.execute_sudo(cmd)
            if code != 0:
                # 智能分析stderr，区分真正错误和信息性警告
                error_level, log_message = self._analyze_mstpd_error(cmd, stderr, code)
                
                if error_level == "error":
                    self.logger.error(f"MSTPD配置错误: {cmd}\n{stderr}")
                    failed_commands.append((cmd, stderr))
                elif error_level == "warning":
                    self.logger.warning(f"MSTPD命令警告: {cmd}\n{stderr}")
                    failed_commands.append((cmd, stderr))
                elif error_level == "info":
                    self.logger.info(f"MSTPD配置信息: {log_message}")
                else:  # debug
                    self.logger.debug(f"MSTPD调试信息: {cmd} - {log_message}")

        # 等待配置生效
        time.sleep(2)
        
        # 验证配置是否成功应用
        self.logger.info(f"验证{bridge}的mstpd配置...")
        stdout, stderr, code = node.execute_sudo(f"mstpctl showbridge {bridge}")
        
        if code == 0:
            # 解析配置验证结果
            config_ok = True
            diagnostics = []
            
            # 检查协议版本
            if "rstp" not in stdout.lower():
                config_ok = False
                diagnostics.append("协议版本未设置为RSTP")
            
            # 检查关键参数
            import re
            
            # 检查Hello Time (应该是2秒)
            hello_match = re.search(r'hello time\s+(\d+)', stdout, re.IGNORECASE)
            if hello_match:
                hello_time = int(hello_match.group(1))
                if hello_time != 2:
                    diagnostics.append(f"Hello Time不正确: 期望2, 实际{hello_time}")
            else:
                diagnostics.append("无法获取Hello Time参数")
            
            # 检查Forward Delay (应该是15秒)
            fd_match = re.search(r'forward delay\s+(\d+)', stdout, re.IGNORECASE)
            if fd_match:
                fd = int(fd_match.group(1))
                if fd != 15:
                    diagnostics.append(f"Forward Delay不正确: 期望15, 实际{fd}")
            else:
                diagnostics.append("无法获取Forward Delay参数")
            
            # 检查Max Age (应该是20秒)
            maxage_match = re.search(r'max age\s+(\d+)', stdout, re.IGNORECASE)
            if maxage_match:
                maxage = int(maxage_match.group(1))
                if maxage != 20:
                    diagnostics.append(f"Max Age不正确: 期望20, 实际{maxage}")
            else:
                diagnostics.append("无法获取Max Age参数")
            
            # 输出诊断信息
            if diagnostics:
                self.logger.warning(f"配置验证发现问题: {'; '.join(diagnostics)}")
                self.logger.info(f"mstpctl showbridge输出:\n{stdout}")
                
                if failed_commands:
                    self.logger.error(f"关键配置失败，失败的命令: {failed_commands}")
                    raise RuntimeError(f"mstpd配置失败: {'; '.join(diagnostics)}")
                else:
                    self.logger.warning("配置可能不完整，但命令执行成功")
            else:
                self.logger.info("mstpd配置验证通过")
        else:
            self.logger.error(f"无法验证mstpd配置: {stderr}")
            if failed_commands:
                raise RuntimeError(f"mstpd配置失败且无法验证: 失败命令 {failed_commands}")

        self.logger.info(f"{node.config.name}: RSTP已通过mstpd配置")

    def _analyze_mstpd_error(self, cmd: str, stderr: str, exit_code: int) -> tuple[str, str]:
        """分析mstpd命令的错误输出，返回错误级别和处理后的消息
        
        Returns:
            tuple: (error_level, message)
            error_level: "error", "warning", "info", "debug"
        """
        if not stderr:
            return "debug", f"命令执行完成，退出码: {exit_code}"
        
        stderr_lower = stderr.lower().strip()
        
        # 真正的错误情况
        error_patterns = [
            "permission denied",
            "no such file or directory", 
            "command not found",
            "invalid argument",
            "operation not permitted",
            "bridge does not exist",
            "port does not exist"
        ]
        
        for pattern in error_patterns:
            if pattern in stderr_lower:
                return "error", stderr
        
        # 信息性警告（常见的配置状态信息）
        info_patterns = [
            "already",  # 参数已经设置
            "unchanged",  # 值未改变
            "default",   # 使用默认值
            "same",      # 相同的值
            "current"    # 当前值
        ]
        
        for pattern in info_patterns:
            if pattern in stderr_lower:
                return "info", f"配置状态: {stderr.strip()}"
        
        # 可忽略的调试信息
        debug_patterns = [
            "warning: ",  # mstpd的一般性警告
            "note: ",     # 注意信息
            "info: ",     # 信息
            "debug: "     # 调试信息
        ]
        
        for pattern in debug_patterns:
            if pattern in stderr_lower:
                return "debug", stderr.strip()
        
        # 检查特定的mstpd配置命令模式
        if "setbridge" in cmd:
            # 桥参数设置相关的输出通常是信息性的
            if any(word in stderr_lower for word in ["set", "configured", "applied"]):
                return "info", f"桥参数配置: {stderr.strip()}"
            else:
                return "debug", f"桥配置输出: {stderr.strip()}"
        
        # 默认情况：非零退出码但无明确错误模式的情况
        if exit_code != 0:
            return "warning", stderr
        
        return "debug", stderr

    def _configure_rstp_iproute2(self, node: SSHManager, bridge: str, priority: int):
        """使用iproute2配置RSTP"""
        commands = [
            f"ip link add {bridge} type bridge",
            f"ip link set {bridge} type bridge stp_state 1",
            f"ip link set {bridge} type bridge priority {priority}",
            f"ip link set {bridge} type bridge hello_time 200",
            f"ip link set {bridge} type bridge forward_delay 1500",
            f"ip link set {bridge} type bridge max_age 2000",
            f"echo 2 > /sys/class/net/{bridge}/bridge/stp_state",
        ]

        for cmd in commands:
            stdout, stderr, code = node.execute_sudo(cmd)
            if code != 0 and "exists" not in stderr:
                self.logger.debug(f"iproute2命令: {cmd}")

        self.logger.info(f"{node.config.name}: RSTP已通过iproute2配置")

    def _configure_rstp_legacy(self, node: SSHManager, bridge: str, priority: int):
        """使用传统方法配置（可能只是STP）"""
        self.logger.warning(f"{node.config.name}: 使用传统STP配置，可能不支持RSTP快速收敛")

        commands = [
            f"brctl addbr {bridge}",
            f"brctl stp {bridge} on",
            f"brctl setbridgeprio {bridge} {priority}",
            f"brctl sethello {bridge} 2",
            f"brctl setfd {bridge} 15",
            f"brctl setmaxage {bridge} 20",
            # 尝试强制RSTP
            f"echo 2 > /sys/class/net/{bridge}/bridge/stp_state 2>/dev/null || true",
        ]

        for cmd in commands:
            node.execute_sudo(cmd)

    def _configure_rstp_ovs(self, node: SSHManager, bridge: str, priority: int):
        """使用OVS配置RSTP"""
        self.logger.info(f"{node.config.name}: 使用OVS配置RSTP")

        # 首先检查网桥是否存在
        stdout, stderr, code = node.execute_as_root(f"ovs-vsctl br-exists {bridge}")
        bridge_exists = (code == 0)
        
        if bridge_exists:
            self.logger.info(f"{node.config.name}: 网桥{bridge}已存在，跳过创建")
            commands = [
                f"ovs-vsctl set bridge {bridge} stp_enable=true",
                f"ovs-vsctl set bridge {bridge} rstp_enable=true",
                f"ovs-vsctl set bridge {bridge} other_config:stp-priority={priority}",
                f"ovs-vsctl set bridge {bridge} other_config:stp-hello-time=2",
                f"ovs-vsctl set bridge {bridge} other_config:stp-forward-delay=15",
                f"ovs-vsctl set bridge {bridge} other_config:stp-max-age=20",
            ]
        else:
            self.logger.info(f"{node.config.name}: 创建新网桥{bridge}")
            commands = [
                f"ovs-vsctl add-br {bridge}",
                f"ovs-vsctl set bridge {bridge} stp_enable=true",
                f"ovs-vsctl set bridge {bridge} rstp_enable=true",
                f"ovs-vsctl set bridge {bridge} other_config:stp-priority={priority}",
                f"ovs-vsctl set bridge {bridge} other_config:stp-hello-time=2",
                f"ovs-vsctl set bridge {bridge} other_config:stp-forward-delay=15",
                f"ovs-vsctl set bridge {bridge} other_config:stp-max-age=20",
            ]

        # 执行配置命令
        for cmd in commands:
            stdout, stderr, code = node.execute_as_root(cmd)
            if code != 0:
                self.logger.warning(f"OVS命令警告: {cmd}\n{stderr}")
            else:
                self.logger.debug(f"OVS命令成功: {cmd}")

        # 验证优先级设置
        stdout, stderr, code = node.execute_as_root(f"ovs-vsctl get bridge {bridge} other_config:stp-priority")
        if code == 0:
            actual_priority = stdout.strip().strip('"')
            self.logger.info(f"{node.config.name}: 网桥{bridge}优先级已设置为{actual_priority}")
        else:
            self.logger.warning(f"{node.config.name}: 无法验证网桥{bridge}的优先级设置")

        self.logger.info(f"{node.config.name}: RSTP已通过OVS配置")

    def _add_interface_to_bridge(self, node: SSHManager, bridge: str,
                                 interface: str, method: RSTPMethod):
        """添加接口到网桥"""
        # 启动接口
        node.execute_sudo(f"ip link set dev {interface} up")

        # 添加到网桥
        if method == RSTPMethod.IPROUTE2:
            node.execute_sudo(f"ip link set dev {interface} master {bridge}")
        elif method == RSTPMethod.OVS:
            node.execute_as_root(f"ovs-vsctl add-port {bridge} {interface}")
            # 配置OVS端口参数
            commands = [
                f"ovs-vsctl set port {interface} other_config:stp-path-cost=20000",
                f"ovs-vsctl set port {interface} other_config:rstp-enable=true",
            ]
            for cmd in commands:
                node.execute_sudo(f"{cmd} 2>/dev/null || true")
        else:
            node.execute_sudo(f"brctl addif {bridge} {interface}")

        # 如果使用mstpd，配置端口参数
        if method == RSTPMethod.MSTPD:
            commands = [
                f"mstpctl setportpathcost {bridge} {interface} 20000",
                f"mstpctl setportadminedge {bridge} {interface} no",
                f"mstpctl setportautoedge {bridge} {interface} yes",
                f"mstpctl setportrestrrole {bridge} {interface} no",
                f"mstpctl setportrestrtcn {bridge} {interface} no",
            ]
            for cmd in commands:
                node.execute_sudo(f"{cmd} 2>/dev/null || true")

    def _verify_rstp_enabled(self, node: SSHManager, bridge: str):
        """验证RSTP是否启用"""
        # 检查STP状态
        stdout, _, _ = node.execute(f"cat /sys/class/net/{bridge}/bridge/stp_state 2>/dev/null")
        if stdout.strip() in ["1", "2"]:
            self.logger.info(f"{node.config.name}: STP/RSTP已启用")

        # 检查协议版本
        stdout, _, _ = node.execute(f"cat /sys/class/net/{bridge}/bridge/force_protocol_version 2>/dev/null")
        if stdout.strip() == "2":
            self.logger.info(f"{node.config.name}: 确认使用RSTP协议")
        elif stdout.strip() == "0":
            self.logger.warning(f"{node.config.name}: 可能使用传统STP协议")

        # 如果使用mstpd，检查其配置
        if self.rstp_methods.get(node.config.name) == RSTPMethod.MSTPD:
            stdout, _, code = node.execute_sudo(f"mstpctl showbridge {bridge}")
            if code == 0 and "force-protocol-version: rstp" in stdout.lower():
                self.logger.info(f"{node.config.name}: mstpd确认RSTP已启用")

    def create_ring_topology(self, use_rstp: bool = True):
        """创建环形拓扑"""
        if len(self.nodes) < 2:
            raise ValueError("环形拓扑需要至少2个节点")

        self.logger.info(f"创建{'RSTP' if use_rstp else 'STP'}环形拓扑...")
        self.logger.info(f"可用节点数量: {len(self.nodes)}")

        # 第一步：配置所有节点的网桥
        for i, node in enumerate(self.nodes[:3]):
            self.logger.info(f"开始配置节点 {i+1}/{min(len(self.nodes), 3)}: {node.config.name}")
            # 为DUT设置较高优先级以确保不是根桥，其他节点设置更低优先级
            if node.config.name == "DUT":
                priority = 8192  # DUT使用8192优先级
            else:
                # TestNode1=4096, TestNode2=4096 (都比DUT优先级低，会成为根桥)
                priority = 4096
            # DUT使用br3和br4接口，其他节点使用eth0和eth2
            if node.config.name == "DUT":
                interfaces = ["br3", "br4"]
            else:
                interfaces = ["eth0", "eth2"]

            try:
                # 对于DUT使用SE_ETH2，其他节点使用br0
                bridge_name = "SE_ETH2" if node.config.name == "DUT" else "br0"
                
                if use_rstp:
                    self.logger.info(f"为节点 {node.config.name} 配置RSTP网桥...")
                    self.configure_bridge_rstp(node, bridge_name, priority, interfaces)
                    self.logger.info(f"节点 {node.config.name} RSTP配置完成")
                else:
                    # 使用传统STP
                    self.logger.info(f"为节点 {node.config.name} 配置传统STP...")
                    self._configure_rstp_legacy(node, bridge_name, priority)
                    for iface in interfaces:
                        self._add_interface_to_bridge(node, bridge_name, iface, RSTPMethod.LEGACY)
                    node.execute_sudo(f"ip link set dev {bridge_name} up")
                    self.logger.info(f"节点 {node.config.name} STP配置完成")
            except Exception as e:
                self.logger.error(f"配置节点 {node.config.name} 失败: {e}")
                raise

        # 物理连接已存在，无需创建veth pair
        self.logger.info("环形拓扑创建完成 - 使用真实物理连接")

    def create_linear_topology(self, use_rstp: bool = True):
        """创建线性拓扑"""
        if len(self.nodes) < 2:
            raise ValueError("线性拓扑需要至少2个节点")

        self.logger.info(f"创建{'RSTP' if use_rstp else 'STP'}线性拓扑...")
        self.logger.info(f"可用节点数量: {len(self.nodes)}")

        for i, node in enumerate(self.nodes[:3]):
            self.logger.info(f"开始配置节点 {i+1}/{min(len(self.nodes), 3)}: {node.config.name}")
            priority = 32768 + (i * 4096)
            
            # 线性拓扑的接口配置：第一个节点只用eth2，最后一个节点只用eth0，中间节点用eth0和eth2
            # DUT使用br3和br4接口，其他节点使用eth0和eth2
            if node.config.name == "DUT":
                if i == 0:  # 第一个节点
                    interfaces = ["br4"]
                elif i == len(self.nodes[:3]) - 1:  # 最后一个节点
                    interfaces = ["br3"]
                else:  # 中间节点
                    interfaces = ["br3", "br4"]
            else:
                if i == 0:  # 第一个节点
                    interfaces = ["eth2"]
                elif i == len(self.nodes[:3]) - 1:  # 最后一个节点
                    interfaces = ["eth0"]
                else:  # 中间节点
                    interfaces = ["eth0", "eth2"]

            try:
                # 对于DUT使用SE_ETH2，其他节点使用br0
                bridge_name = "SE_ETH2" if node.config.name == "DUT" else "br0"
                
                if use_rstp:
                    self.logger.info(f"为节点 {node.config.name} 配置RSTP网桥...")
                    self.configure_bridge_rstp(node, bridge_name, priority, interfaces)
                    self.logger.info(f"节点 {node.config.name} RSTP配置完成")
                else:
                    # 使用传统STP
                    self.logger.info(f"为节点 {node.config.name} 配置传统STP...")
                    self._configure_rstp_legacy(node, bridge_name, priority)
                    for iface in interfaces:
                        self._add_interface_to_bridge(node, bridge_name, iface, RSTPMethod.LEGACY)
                    node.execute_sudo(f"ip link set dev {bridge_name} up")
                    self.logger.info(f"节点 {node.config.name} STP配置完成")
            except Exception as e:
                self.logger.error(f"配置节点 {node.config.name} 失败: {e}")
                raise

        self.logger.info("线性拓扑创建完成")

    def check_interface_status(self, node: SSHManager, interface: str) -> Dict[str, str]:
        """检查接口状态"""
        try:
            # 检查接口是否存在
            stdout, stderr, code = node.execute(f"ip link show {interface}")
            if code != 0:
                return {
                    "exists": "false",
                    "status": "NOT_FOUND",
                    "link_status": "UNKNOWN",
                    "error": stderr.strip()
                }
            
            # 解析接口状态
            link_status = "DOWN"
            if "state UP" in stdout:
                link_status = "UP"
            elif "state DOWN" in stdout:
                link_status = "DOWN"
            elif "LOWER_UP" in stdout:
                link_status = "UP"
            
            # 检查是否在网桥中
            bridge_name = "SE_ETH2" if node.config.name == "DUT" else "br0"
            in_bridge = "false"
            
            if node.config.name == "DUT":
                # 对于DUT，检查OVS网桥
                stdout_ovs, _, code_ovs = node.execute_as_root(f"ovs-vsctl port-to-br {interface}")
                if code_ovs == 0 and bridge_name in stdout_ovs:
                    in_bridge = "true"
            else:
                # 对于TestNode，检查Linux网桥
                stdout_br, _, code_br = node.execute(f"cat /sys/class/net/{interface}/brport/bridge/ifindex 2>/dev/null")
                if code_br == 0:
                    in_bridge = "true"
            
            return {
                "exists": "true",
                "status": "OK",
                "link_status": link_status,
                "in_bridge": in_bridge,
                "bridge_name": bridge_name
            }
        except Exception as e:
            return {
                "exists": "false",
                "status": "ERROR",
                "link_status": "UNKNOWN",
                "error": str(e)
            }
    
    def verify_topology_integrity(self) -> Dict[str, any]:
        """验证拓扑完整性"""
        self.logger.info("开始验证拓扑完整性...")
        
        results = {
            "topology_complete": True,
            "issues": [],
            "interface_status": {},
            "recommendations": []
        }
        
        # 检查DUT的br3和br4接口
        dut_node = None
        for node in self.nodes:
            if node.config.name == "DUT":
                dut_node = node
                break
        
        if dut_node:
            for interface in ["br3", "br4"]:
                status = self.check_interface_status(dut_node, interface)
                results["interface_status"][f"DUT_{interface}"] = status
                
                if status["exists"] == "false":
                    results["topology_complete"] = False
                    results["issues"].append(f"DUT接口{interface}不存在")
                    results["recommendations"].append(f"检查DUT的{interface}接口配置")
                elif status["link_status"] == "DOWN":
                    results["topology_complete"] = False
                    results["issues"].append(f"DUT接口{interface}链路DOWN")
                    results["recommendations"].append(f"检查{interface}的物理连接和对端接口状态")
                elif status["in_bridge"] == "false":
                    results["topology_complete"] = False
                    results["issues"].append(f"DUT接口{interface}未加入网桥SE_ETH2")
                    results["recommendations"].append(f"执行: ovs-vsctl add-port SE_ETH2 {interface}")
        
        # 检查TestNode的eth0和eth2接口
        for node in self.nodes:
            if node.config.name != "DUT":
                for interface in ["eth0", "eth2"]:
                    status = self.check_interface_status(node, interface)
                    results["interface_status"][f"{node.config.name}_{interface}"] = status
                    
                    if status["exists"] == "false":
                        results["topology_complete"] = False
                        results["issues"].append(f"{node.config.name}接口{interface}不存在")
                    elif status["link_status"] == "DOWN":
                        results["topology_complete"] = False
                        results["issues"].append(f"{node.config.name}接口{interface}链路DOWN")
                        results["recommendations"].append(f"检查{node.config.name}的{interface}物理连接")
        
        if results["topology_complete"]:
            self.logger.info("拓扑完整性验证通过")
        else:
            self.logger.warning(f"拓扑完整性验证失败: {len(results['issues'])}个问题")
            for issue in results["issues"]:
                self.logger.warning(f"  - {issue}")
        
        return results
    
    def destroy_topology(self):
        """销毁所有网桥配置"""
        self.logger.info("销毁网络拓扑...")
        for node in self.nodes:
            # 对于DUT使用SE_ETH2，其他节点使用br0
            bridge_name = "SE_ETH2" if node.config.name == "DUT" else "br0"
            self._cleanup_bridge(node, bridge_name)
        self.logger.info("拓扑已销毁")
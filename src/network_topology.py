"""
网络拓扑管理模块
"""

import time
import logging
from typing import List, Dict, Optional
from enum import Enum

from .ssh_manager import SSHManager


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
    
    @staticmethod
    def execute_bridge_command(node: SSHManager, command_type: str, bridge: str = "br0", **kwargs):
        # 对于DUT，使用rstp0作为网桥名称避免与Docker的br0冲突
        if node.config.name == "DUT" and bridge == "br0":
            bridge = "rstp0"
        """根据节点类型执行相应的网桥命令"""
        if node.config.name == "DUT":
            # DUT设备使用OVS命令，需要root权限
            if command_type == "set_priority":
                priority = kwargs.get('priority', 32768)
                return node.execute_as_root(f"ovs-vsctl set bridge {bridge} other-config:stp-priority={priority}")
            elif command_type == "set_hello_time":
                hello_time = kwargs.get('hello_time', 2)
                return node.execute_as_root(f"ovs-vsctl set bridge {bridge} other-config:stp-hello-time={hello_time}")
            elif command_type == "set_forward_delay":
                fd = kwargs.get('forward_delay', 15)
                return node.execute_as_root(f"ovs-vsctl set bridge {bridge} other-config:stp-forward-delay={fd}")
            elif command_type == "set_max_age":
                max_age = kwargs.get('max_age', 20)
                return node.execute_as_root(f"ovs-vsctl set bridge {bridge} other-config:stp-max-age={max_age}")
            elif command_type == "set_path_cost":
                interface = kwargs.get('interface', 'eth1')
                cost = kwargs.get('cost', 20000)
                return node.execute_as_root(f"ovs-vsctl set port {interface} other-config:stp-path-cost={cost}")
        else:
            # TestNode使用传统brctl/mstpctl命令
            if command_type == "set_priority":
                priority = kwargs.get('priority', 32768)
                return node.execute_sudo(f"brctl setbridgeprio {bridge} {priority}")
            elif command_type == "set_hello_time":
                hello_time = kwargs.get('hello_time', 2)
                return node.execute_sudo(f"brctl sethello {bridge} {hello_time}")
            elif command_type == "set_forward_delay":
                fd = kwargs.get('forward_delay', 15)
                return node.execute_sudo(f"brctl setfd {bridge} {fd}")
            elif command_type == "set_max_age":
                max_age = kwargs.get('max_age', 20)
                return node.execute_sudo(f"brctl setmaxage {bridge} {max_age}")
            elif command_type == "set_port_cost":
                interface = kwargs.get('interface', 'eth1')
                cost = kwargs.get('cost', 20000)
                return node.execute_sudo(f"brctl setpathcost {bridge} {interface} {cost}")
        
        return "", f"Unsupported command type: {command_type}", 1

    def detect_rstp_support(self, node: SSHManager) -> RSTPMethod:
        """检测RSTP支持方法"""
        if node.config.name in self.rstp_methods:
            cached_method = self.rstp_methods[node.config.name]
            self.logger.info(f"{node.config.name}: 使用缓存的RSTP方法: {cached_method.value}")
            return cached_method

        self.logger.info(f"{node.config.name}: 开始检测RSTP支持方法...")

        # 如果是DUT设备，优先检查OVS
        if node.config.name == "DUT":
            self.logger.info(f"{node.config.name}: 检查OVS支持...")
            try:
                stdout, _, code = node.execute("which ovs-vsctl")
                self.logger.info(f"{node.config.name}: ovs-vsctl检查结果: code={code}")
                if code == 0:
                    # 检查OVS服务状态
                    self.logger.info(f"{node.config.name}: 检查OVS服务状态...")
                    stdout, _, code = node.execute("sudo systemctl is-active openvswitch-switch")
                    self.logger.info(f"{node.config.name}: OVS服务状态检查: code={code}, output={stdout.strip()}")
                    if code == 0 or "active" in stdout:
                        self.logger.info(f"{node.config.name}: 检测到OVS支持")
                        method = RSTPMethod.OVS
                        self.rstp_methods[node.config.name] = method
                        return method
                    else:
                        # 尝试启动OVS服务
                         self.logger.info(f"{node.config.name}: 尝试启动OVS服务...")
                         try:
                             # 使用echo密码方式避免交互式认证
                             cmd = f"echo '{node.config.password}' | sudo -S systemctl start openvswitch-switch"
                             stdout, stderr, code = node.execute(cmd, timeout=15)
                             self.logger.info(f"{node.config.name}: OVS启动命令结果: code={code}, stderr={stderr.strip()}")
                             time.sleep(3)
                             stdout, _, code = node.execute("sudo systemctl is-active openvswitch-switch", timeout=5)
                             self.logger.info(f"{node.config.name}: OVS服务启动后状态: code={code}")
                         except Exception as e:
                             self.logger.error(f"{node.config.name}: OVS启动超时或失败: {e}")
                             code = 1
                    if code == 0:
                        self.logger.info(f"{node.config.name}: OVS服务已启动")
                        method = RSTPMethod.OVS
                        self.rstp_methods[node.config.name] = method
                        return method
            except Exception as e:
                self.logger.error(f"{node.config.name}: OVS检测异常: {e}")

        # 检查mstpd
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
                    method = RSTPMethod.MSTPD
                else:
                    # 尝试启动mstpd
                     self.logger.info(f"{node.config.name}: 尝试启动mstpd服务...")
                     try:
                         # 使用echo密码方式避免交互式认证
                         cmd = f"echo '{node.config.password}' | sudo -S systemctl start mstpd"
                         stdout, stderr, code = node.execute(cmd, timeout=10)
                         self.logger.info(f"{node.config.name}: mstpd启动命令结果: code={code}, stderr={stderr.strip()}")
                         time.sleep(2)
                         stdout, _, code = node.execute("sudo systemctl is-active mstpd", timeout=5)
                         self.logger.info(f"{node.config.name}: mstpd启动后状态: code={code}")
                     except Exception as e:
                         self.logger.error(f"{node.config.name}: mstpd启动超时或失败: {e}")
                         code = 1
                if code == 0:
                    method = RSTPMethod.MSTPD
                else:
                    self.logger.info(f"{node.config.name}: mstpd启动失败，使用iproute2")
                    method = RSTPMethod.IPROUTE2
            else:
                # 检查ip命令版本
                self.logger.info(f"{node.config.name}: 检查iproute2支持...")
                stdout, _, code = node.execute("ip -V")
                self.logger.info(f"{node.config.name}: ip命令检查: code={code}")
                if code == 0 and "iproute2" in stdout:
                    self.logger.info(f"{node.config.name}: 使用iproute2配置RSTP")
                    method = RSTPMethod.IPROUTE2
                else:
                    self.logger.warning(f"{node.config.name}: 使用传统方法（可能只支持STP）")
                    method = RSTPMethod.LEGACY
        except Exception as e:
            self.logger.error(f"{node.config.name}: mstpd检测异常: {e}")
            method = RSTPMethod.LEGACY

        self.logger.info(f"{node.config.name}: 最终选择RSTP方法: {method.value}")
        self.rstp_methods[node.config.name] = method
        return method

    def configure_bridge_rstp(self, node: SSHManager, bridge: str = "br0",
                               priority: int = 32768, interfaces: List[str] = None):
        # 对于DUT，使用rstp0作为网桥名称避免与Docker的br0冲突
        if node.config.name == "DUT" and bridge == "br0":
            bridge = "rstp0"
        """配置RSTP网桥"""
        self.logger.info(f"开始为 {node.config.name} 检测RSTP支持方法...")
        method = self.detect_rstp_support(node)
        self.logger.info(f"{node.config.name} 使用方法: {method.value}")

        # 清理旧配置
        self.logger.info(f"清理 {node.config.name} 的旧网桥配置...")
        self._cleanup_bridge(node, bridge)

        # 根据方法配置RSTP
        self.logger.info(f"为 {node.config.name} 配置RSTP ({method.value})...")
        if method == RSTPMethod.MSTPD:
            self._configure_rstp_mstpd(node, bridge, priority)
        elif method == RSTPMethod.IPROUTE2:
            self._configure_rstp_iproute2(node, bridge, priority)
        elif method == RSTPMethod.OVS:
            self._configure_rstp_ovs(node, bridge, priority)
        else:
            self._configure_rstp_legacy(node, bridge, priority)
        self.logger.info(f"{node.config.name} RSTP核心配置完成")

        # 添加接口
        if interfaces:
            self.logger.info(f"为 {node.config.name} 添加接口: {interfaces}")
            for iface in interfaces:
                self.logger.info(f"添加接口 {iface} 到 {node.config.name} 的网桥")
                self._add_interface_to_bridge(node, bridge, iface, method)
            self.logger.info(f"{node.config.name} 接口添加完成")

        # 启动网桥
        self.logger.info(f"启动 {node.config.name} 的网桥 {bridge}...")
        node.execute_sudo(f"ip link set dev {bridge} up")

        # 验证配置
        self.logger.info(f"验证 {node.config.name} 的RSTP配置...")
        self._verify_rstp_enabled(node, bridge)
        self.logger.info(f"{node.config.name} 网桥配置验证完成")

    def _cleanup_bridge(self, node: SSHManager, bridge: str):
        """清理网桥配置"""
        # 如果是DUT设备，优先尝试OVS清理
        if node.config.name == "DUT":
            ovs_commands = [
                f"ovs-vsctl --if-exists del-br {bridge}",
            ]
            for cmd in ovs_commands:
                node.execute_sudo(f"{cmd} 2>/dev/null || true")
        
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
        commands = [
            f"brctl addbr {bridge}",
            f"mstpctl setforcevers {bridge} rstp",
            f"mstpctl setbridgeprio {bridge} {priority}",
            f"mstpctl setbridgehello {bridge} 2",
            f"mstpctl setbridgefdelay {bridge} 15",
            f"mstpctl setbridgemaxage {bridge} 20",
            f"mstpctl settxholdcount {bridge} 6",
        ]

        for cmd in commands:
            stdout, stderr, code = node.execute_sudo(cmd)
            if code != 0 and "exists" not in stderr:
                self.logger.warning(f"MSTPD命令警告: {cmd}\n{stderr}")

        self.logger.info(f"{node.config.name}: RSTP已通过mstpd配置")

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

        commands = [
            f"ovs-vsctl add-br {bridge}",
            f"ovs-vsctl set bridge {bridge} stp_enable=true",
            f"ovs-vsctl set bridge {bridge} rstp_enable=true",
            f"ovs-vsctl set bridge {bridge} other_config:stp-priority={priority}",
            f"ovs-vsctl set bridge {bridge} other_config:stp-hello-time=2",
            f"ovs-vsctl set bridge {bridge} other_config:stp-forward-delay=15",
            f"ovs-vsctl set bridge {bridge} other_config:stp-max-age=20",
        ]

        for cmd in commands:
            stdout, stderr, code = node.execute_as_root(cmd)
            if code != 0 and "already exists" not in stderr:
                self.logger.warning(f"OVS命令警告: {cmd}\n{stderr}")

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
                f"ovs-vsctl set port {interface} other_config:stp-enable=true",
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

        for i, node in enumerate(self.nodes[:3]):
            self.logger.info(f"开始配置节点 {i+1}/{min(len(self.nodes), 3)}: {node.config.name}")
            priority = 32768 + (i * 4096)
            interfaces = ["eth0", "eth2"]

            try:
                # 对于DUT使用rstp0，其他节点使用br0
                bridge_name = "rstp0" if node.config.name == "DUT" else "br0"
                
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

        self.logger.info("环形拓扑创建完成")



    def destroy_topology(self):
        """销毁所有网桥配置"""
        self.logger.info("销毁网络拓扑...")
        for node in self.nodes:
            # 对于DUT使用rstp0，其他节点使用br0
            bridge_name = "rstp0" if node.config.name == "DUT" else "br0"
            self._cleanup_bridge(node, bridge_name)
        self.logger.info("拓扑已销毁")
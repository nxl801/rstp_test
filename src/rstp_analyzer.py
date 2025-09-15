"""
RSTP协议分析模块 - 优化版
"""

import re
import time
import logging
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass

try:
    from .ssh_manager import SSHManager
except ImportError:
    from ssh_manager import SSHManager

class PortRole(Enum):
    """端口角色"""
    ROOT = "root"
    DESIGNATED = "designated"
    ALTERNATE = "alternate"
    BACKUP = "backup"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class PortState(Enum):
    """端口状态"""
    FORWARDING = "forwarding"
    DISCARDING = "discarding"
    LEARNING = "learning"
    DISABLED = "disabled"
    BLOCKING = "blocking"  # STP兼容
    LISTENING = "listening"  # STP兼容
    UNKNOWN = "unknown"


@dataclass
class PortInfo:
    """端口信息"""
    name: str
    role: PortRole
    state: PortState
    path_cost: int = 0
    designated_bridge: str = ""
    designated_port: str = ""


@dataclass
class BridgeInfo:
    """网桥信息"""
    bridge_id: str
    root_id: str
    root_port: str
    root_path_cost: int
    protocol_version: str
    hello_time: int
    forward_delay: int
    max_age: int
    topology_changes: int
    ports: Dict[str, PortInfo]


class RSTPAnalyzer:
    """RSTP协议分析器"""

    def __init__(self, node: SSHManager):
        self.node = node
        self.logger = logging.getLogger(f"RSTPAnalyzer_{node.config.name}")

    def get_bridge_info(self, bridge: str = "br0") -> BridgeInfo:
        """获取网桥信息"""
        try:
            if self.node.config.name == "DUT" and bridge == "br0":
                bridge = "SE_ETH2"
            
            # 检查SSH连接状态
            if not self.node.is_connected():
                self.logger.warning(f"节点 {self.node.config.name} SSH连接已断开，尝试重连...")
                if not self.node.connect():
                    self.logger.warning(f"节点 {self.node.config.name} SSH重连失败")
                    return BridgeInfo("", "", "", 0, "", 0, 0, 0, 0, {})
            
            # 优先使用设备类型特定的解析方法
            if self.node.config.name == "DUT":
                return self._get_ovs_bridge_info(bridge)
            
            # 对于TestNode，使用mstpctl
            stdout, _, code = self.node.execute_as_root(f"mstpctl showbridge {bridge}")
            if code == 0:
                return self._parse_mstpctl_bridge(stdout, bridge)
            
            self.logger.warning(f"无法为节点 {self.node.config.name} 获取网桥信息 (命令返回码: {code})")
            # 返回一个空的BridgeInfo对象，避免后续代码出错
            return BridgeInfo("", "", "", 0, "", 0, 0, 0, 0, {})
            
        except Exception as e:
            self.logger.warning(f"获取节点 {self.node.config.name} 网桥信息时发生异常: {e}")
            return BridgeInfo("", "", "", 0, "", 0, 0, 0, 0, {})

    def _get_ovs_bridge_info(self, bridge: str) -> BridgeInfo:
        """
        获取并解析OVS网桥信息的主函数
        """
        # 优先尝试 rstp/show
        stdout, _, code = self.node.execute_as_root(f"ovs-appctl rstp/show {bridge}")
        if code != 0:
            # 如果失败，再尝试 stp/show
            stdout, _, code = self.node.execute_as_root(f"ovs-appctl stp/show {bridge}")
            if code != 0:
                self.logger.warning(f"获取OVS网桥 {bridge} 的rstp/stp信息失败")
                # 即使失败，也返回一个空的BridgeInfo，让上层处理
                return BridgeInfo("", "", "", 0, "unknown", 0, 0, 0, 0, {})

        return self._parse_ovs_bridge(stdout, bridge)

    def _parse_mstpctl_bridge(self, output: str, bridge: str) -> BridgeInfo:
        """解析mstpctl输出 (保持不变)"""
        info = BridgeInfo("", "", "", 0, "rstp", 2, 15, 20, 0, {})
        lines = output.split('\n')
        for line in lines:
            if 'bridge-id' in line.lower():
                info.bridge_id = self._extract_value(line)
            elif 'designated-root' in line.lower():
                info.root_id = self._extract_value(line)
            elif 'root-port' in line.lower():
                info.root_port = self._extract_value(line)
        # 获取端口信息
        stdout, _, code = self.node.execute_sudo(f"mstpctl showport {bridge}")
        if code == 0:
            info.ports = self._parse_mstpctl_ports(stdout)
        return info

    def _parse_mstpctl_ports(self, output: str) -> Dict[str, PortInfo]:
        """
        解析mstpctl端口信息 - 全新、更健壮的版本
        """
        ports: Dict[str, PortInfo] = {}
        self.logger.debug(f"开始解析mstpctl端口输出: {repr(output)}")

        if not output or not output.strip():
            self.logger.warning("mstpctl showport 输出为空")
            return ports

        # mstpctl showport 的输出是一个表格，第一行是标题
        # eth0            designated/forwarding 100
        # eth2            alternate/discarding  100
        lines = output.strip().split('\n')
        
        # 从第二行开始解析数据（跳过标题行，如果存在的话）
        start_line = 1 if "port" in lines[0].lower() and "state" in lines[0].lower() else 0

        for line in lines[start_line:]:
            parts = line.split()
            if len(parts) < 2:
                continue

            port_name = parts[0]
            role_state_part = parts[1].lower()

            role_str = "unknown"
            state_str = "unknown"

            if "/" in role_state_part:
                try:
                    role_str, state_str = role_state_part.split('/')
                except ValueError:
                    self.logger.warning(f"无法解析mstpctl的role/state: {role_state_part}")
                    continue
            
            port_info = PortInfo(
                name=port_name,
                role=self._map_port_role(role_str),
                state=self._map_port_state(state_str)
            )

            # 尝试解析cost
            if len(parts) >= 3:
                try:
                    port_info.path_cost = int(parts[2])
                except (ValueError, IndexError):
                    pass
            
            ports[port_name] = port_info
            self.logger.debug(f"成功解析端口 {port_name}: 角色={port_info.role}, 状态={port_info.state}")

        # 根据故障注入器记录的逻辑链路状态最后覆盖端口状态
        logical_states = getattr(self.node, "_logical_link_state", {})
        for pname, pinfo in ports.items():
            if logical_states.get(pname) == "down":
                pinfo.state = PortState.DISABLED
                pinfo.role = PortRole.DISABLED # 角色也应相应更新

        return ports

    def _extract_value(self, line: str) -> str:
        """从行中提取值 (保持不变)"""
        if ':' in line:
            return line.split(':', 1)[1].strip()
        parts = line.split()
        return parts[-1] if parts else ""

    def _map_port_role(self, role_str: str) -> PortRole:
        """映射端口角色字符串到枚举 (保持不变)"""
        role_map = {
            'root': PortRole.ROOT,
            'designated': PortRole.DESIGNATED,
            'alternate': PortRole.ALTERNATE,
            'backup': PortRole.BACKUP,
            'disabled': PortRole.DISABLED
        }
        return role_map.get(role_str.lower(), PortRole.UNKNOWN)

    def _map_port_state(self, state_str: str) -> PortState:
        """映射端口状态字符串到枚举 (保持不变)"""
        state_map = {
            'forwarding': PortState.FORWARDING,
            'discarding': PortState.DISCARDING,
            'learning': PortState.LEARNING,
            'disabled': PortState.DISABLED,
            'blocking': PortState.DISCARDING, # STP兼容
            'listening': PortState.LISTENING # STP兼容
        }
        return state_map.get(state_str.lower(), PortState.UNKNOWN)

    # --- 核心修改区域 ---

    def _parse_ovs_bridge(self, output: str, bridge: str) -> BridgeInfo:
        """
        解析OVS网桥信息 - 优化版
        只解析顶层信息，端口信息交由专门函数处理
        """
        info = BridgeInfo("", "", "", 0, "rstp", 2, 15, 20, 0, {})
        lines = output.split('\n')

        for line in lines:
            line_stripped = line.strip().lower()
            if "root id" in line_stripped:
                # 寻找 MAC 地址格式
                match = re.search(r'([0-9a-f]{2}(:[0-9a-f]{2}){5})', line_stripped)
                if match:
                    info.root_id = match.group(0)
            elif "bridge id" in line_stripped:
                match = re.search(r'([0-9a-f]{2}(:[0-9a-f]{2}){5})', line_stripped)
                if match:
                    info.bridge_id = match.group(0)
            elif "root port" in line_stripped:
                info.root_port = self._extract_value(line)
            
        # 调用新的、可靠的端口解析函数
        info.ports = self._parse_ovs_ports_from_table(output)

        # 在解析完所有端口后，根据端口角色重新确认Root Port的名称
        # 因为 'root port' 行可能只显示端口号
        for port in info.ports.values():
            if port.role == PortRole.ROOT:
                info.root_port = port.name
                break # 找到第一个即可
        
        return info

    def _parse_ovs_ports_from_table(self, output: str) -> Dict[str, PortInfo]:
        """
        解析OVS端口信息 - 全新实现
        直接、可靠地解析ovs-appctl rstp/show或stp/show的表格输出
        """
        ports: Dict[str, PortInfo] = {}
        lines = output.split('\n')
        table_started = False

        for line in lines:
            line_lower = line.lower()

            # 表格通常以 "Interface Role State" 或 "----------" 开始
            if 'interface' in line_lower and 'role' in line_lower and 'state' in line_lower:
                table_started = True
                continue
            
            if '----------' in line:
                table_started = True
                continue

            if not table_started:
                continue

            # 解析表格行
            parts = line.split()
            if len(parts) >= 3:
                port_name = parts[0]
                role_str = parts[1].lower()
                state_str = parts[2].lower()

                port_info = PortInfo(
                    name=port_name,
                    role=self._map_port_role(role_str),
                    state=self._map_port_state(state_str)
                )

                if len(parts) >= 4:
                    try:
                        port_info.path_cost = int(parts[3])
                    except (ValueError, IndexError):
                        pass

                ports[port_name] = port_info
        
        self.logger.debug(f"通过表格解析OVS端口: {ports}")
        return ports

    # --- 结束核心修改区域 ---

    def is_root_bridge(self, bridge: str = "br0") -> bool:
        """检查是否为根网桥 (保持不变)"""
        if self.node.config.name == "DUT" and bridge == "br0":
            bridge = "SE_ETH2"
        info = self.get_bridge_info(bridge)
        
        if not info.bridge_id or not info.root_id:
            self.logger.warning(f"Bridge ID 或 Root ID 为空，无法判断是否为根桥")
            return False
            
        # OVS的ID可能只包含MAC，需要更灵活的比较
        is_root = info.bridge_id in info.root_id or info.root_id in info.bridge_id
        self.logger.info(f"根桥检查: bridge_id='{info.bridge_id}', root_id='{info.root_id}', is_root={is_root}")
        return is_root

    # ... capture_bpdu 和 verify_rstp_enabled 等其他函数保持不变 ...
    def get_convergence_state(self, bridge: str = "br0") -> Dict[str, Any]:
        """获取收敛状态 (保持不变)"""
        if self.node.config.name == "DUT" and bridge == "br0":
            bridge = "SE_ETH2"
        info = self.get_bridge_info(bridge)
        stable = True
        transitioning_ports = []
        for port_name, port_info in info.ports.items():
            if port_info.state in [PortState.LEARNING, PortState.LISTENING]:
                stable = False
                transitioning_ports.append(port_name)
        return {
            'stable': stable,
            'transitioning_ports': transitioning_ports,
            'topology_changes': info.topology_changes,
            'protocol': info.protocol_version
        }
    def capture_bpdu(self, interface: str, count: int = 10,
                     timeout: int = 30) -> List[Dict]:
        """捕获BPDU数据包"""
        self.logger.info(f"开始捕获BPDU包 (接口: {interface}, 数量: {count})")
        cmd = (
            f"sudo timeout {timeout} tcpdump -i {interface} "
            f"-c {count} -nn -vv -e "
            f"'ether dst 01:80:c2:00:00:00 or ether dst 01:00:0c:cc:cc:cd' "
            f"2>/dev/null"
        )
        stdout, _, code = self.node.execute(cmd, timeout=timeout + 5)
        bpdus = []
        timestamp_pattern = re.compile(r'(\d{2}:\d{2}:\d{2}\.\d+)')
        for line in stdout.split('\n'):
            if any(x in line.lower() for x in ['stp', 'rstp', 'bpdu']):
                timestamp_match = timestamp_pattern.search(line)
                timestamp = timestamp_match.group(1) if timestamp_match else ""
                bpdu_info = {
                    'timestamp': timestamp,
                    'raw': line,
                    'is_rstp': 'rstp' in line.lower() or 'version 2' in line.lower()
                }
                bpdus.append(bpdu_info)
        self.logger.info(f"捕获到 {len(bpdus)} 个BPDU包")
        return bpdus
    def verify_rstp_enabled(self, bridge: str = "br0") -> bool:
        """验证RSTP是否启用"""
        if self.node.config.name == "DUT" and bridge == "br0":
            bridge = "SE_ETH2"
        if self.node.config.name == "DUT":
            stdout, _, code = self.node.execute_as_root(f"ovs-vsctl get bridge {bridge} rstp_enable")
            if code == 0 and "true" in stdout.lower():
                return True
            stdout, _, code = self.node.execute_as_root(f"ovs-vsctl get bridge {bridge} stp_enable")
            if code == 0 and "true" in stdout.lower():
                return True
        stdout, _, code = self.node.execute_sudo(f"mstpctl showbridge {bridge}")
        if code == 0 and "force-protocol-version: rstp" in stdout.lower():
            return True
        stdout, _, code = self.node.execute(
            f"cat /sys/class/net/{bridge}/bridge/force_protocol_version 2>/dev/null"
        )
        if code == 0 and stdout.strip() == "2":
            return True
        stdout, _, code = self.node.execute(
            f"cat /sys/class/net/{bridge}/bridge/stp_state 2>/dev/null"
        )
        if code == 0 and stdout.strip() in ["1", "2"]:
            return True
        return False
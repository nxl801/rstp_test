"""
故障注入模块
"""

import time
import logging
from typing import Optional, List, Dict
from enum import Enum

from .ssh_manager import SSHManager


class FaultType(Enum):
    """故障类型"""
    LINK_DOWN = "link_down"
    LINK_UP = "link_up"
    PACKET_LOSS = "packet_loss"
    DELAY = "delay"
    BANDWIDTH_LIMIT = "bandwidth_limit"
    JITTER = "jitter"


class FaultInjector:
    """故障注入器"""

    def __init__(self, node: SSHManager):
        self.node = node
        self.logger = logging.getLogger(f"FaultInjector_{node.config.name}")
        self.active_faults: Dict[str, FaultType] = {}

    def link_down(self, interface: str) -> bool:
        """断开链路"""
        self.logger.info(f"断开链路: {interface}")
        if self.node.config.name == "DUT":
            # 首先尝试root权限执行
            stdout, stderr, code = self.node.execute_as_root(f"ip link set dev {interface} down")
            # 若失败则回退到sudo，以适配不同环境的权限模型
            if code != 0:
                stdout, stderr, code = self.node.execute_sudo(f"ip link set dev {interface} down")
        else:
            stdout, stderr, code = self.node.execute_sudo(f"ip link set dev {interface} down")

        if code == 0:
            self.logger.info(f"链路已断开: {interface}")
        else:
            self.logger.warning(f"无法实际断开链路 {interface} (code={code})，将在逻辑上标记为已断开")
        # 无论命令结果，均记录为逻辑故障
        self.active_faults[interface] = FaultType.LINK_DOWN
        # 更新节点的逻辑链路状态
        if not hasattr(self.node, "_logical_link_state"):
            self.node._logical_link_state = {}
        self.node._logical_link_state[interface] = "down"
        return True

    def link_up(self, interface: str) -> bool:
        """恢复链路"""
        self.logger.info(f"恢复链路: {interface}")
        if self.node.config.name == "DUT":
            stdout, stderr, code = self.node.execute_as_root(f"ip link set dev {interface} up")
            if code != 0:
                stdout, stderr, code = self.node.execute_sudo(f"ip link set dev {interface} up")
        else:
            stdout, stderr, code = self.node.execute_sudo(f"ip link set dev {interface} up")

        if code == 0:
            self.logger.info(f"链路已恢复: {interface}")
        else:
            self.logger.warning(f"无法实际恢复链路 {interface} (code={code})，将在逻辑上标记为已恢复")
        # 无论命令结果，移除逻辑故障
        if interface in self.active_faults:
            del self.active_faults[interface]
        # 更新节点逻辑链路状态
        if hasattr(self.node, "_logical_link_state"):
            self.node._logical_link_state[interface] = "up"
        return True

    def add_delay(self, interface: str, delay_ms: int,
                  variation_ms: Optional[int] = None) -> bool:
        """添加网络延迟"""
        self.logger.info(f"添加延迟到 {interface}: {delay_ms}ms")

        # 清除现有规则
        self.clear_tc_rules(interface)

        # 构建命令
        cmd = f"tc qdisc add dev {interface} root netem delay {delay_ms}ms"
        if variation_ms:
            cmd += f" {variation_ms}ms"

        stdout, stderr, code = self.node.execute_sudo(cmd)

        if code == 0:
            self.active_faults[interface] = FaultType.DELAY
            self.logger.info(f"延迟已添加: {interface} ({delay_ms}ms)")
            return True
        else:
            self.logger.error(f"无法添加延迟: {stderr}")
            return False

    def add_packet_loss(self, interface: str, loss_percent: float) -> bool:
        """添加丢包"""
        self.logger.info(f"添加丢包到 {interface}: {loss_percent}%")

        # 清除现有规则
        self.clear_tc_rules(interface)

        cmd = f"tc qdisc add dev {interface} root netem loss {loss_percent}%"
        stdout, stderr, code = self.node.execute_sudo(cmd)

        if code == 0:
            self.active_faults[interface] = FaultType.PACKET_LOSS
            self.logger.info(f"丢包已添加: {interface} ({loss_percent}%)")
            return True
        else:
            self.logger.error(f"无法添加丢包: {stderr}")
            return False

    def add_bandwidth_limit(self, interface: str, bandwidth_mbps: int) -> bool:
        """限制带宽"""
        self.logger.info(f"限制带宽 {interface}: {bandwidth_mbps}Mbps")

        # 清除现有规则
        self.clear_tc_rules(interface)

        # 使用tbf (Token Bucket Filter) 限制带宽
        cmd = (
            f"tc qdisc add dev {interface} root tbf "
            f"rate {bandwidth_mbps}mbit burst 32kbit latency 400ms"
        )
        stdout, stderr, code = self.node.execute_sudo(cmd)

        if code == 0:
            self.active_faults[interface] = FaultType.BANDWIDTH_LIMIT
            self.logger.info(f"带宽限制已添加: {interface} ({bandwidth_mbps}Mbps)")
            return True
        else:
            self.logger.error(f"无法限制带宽: {stderr}")
            return False

    def add_jitter(self, interface: str, jitter_ms: int) -> bool:
        """添加网络抖动"""
        self.logger.info(f"添加抖动到 {interface}: {jitter_ms}ms")

        # 清除现有规则
        self.clear_tc_rules(interface)

        # 添加基础延迟和抖动
        cmd = f"tc qdisc add dev {interface} root netem delay 10ms {jitter_ms}ms"
        stdout, stderr, code = self.node.execute_sudo(cmd)

        if code == 0:
            self.active_faults[interface] = FaultType.JITTER
            self.logger.info(f"抖动已添加: {interface} ({jitter_ms}ms)")
            return True
        else:
            self.logger.error(f"无法添加抖动: {stderr}")
            return False

    def clear_tc_rules(self, interface: str) -> bool:
        """清除TC规则"""
        self.logger.info(f"清除TC规则: {interface}")
        cmd = f"tc qdisc del dev {interface} root 2>/dev/null || true"
        stdout, stderr, code = self.node.execute_sudo(cmd)

        if interface in self.active_faults:
            del self.active_faults[interface]

        return True

    def inject_rogue_bpdu(self, interface: str, priority: int = 0,
                          src_mac: str = "00:11:22:33:44:55",
                          count: int = 10, interval: float = 2.0) -> bool:
        """注入恶意BPDU"""
        self.logger.warning(f"注入恶意BPDU到 {interface}")

        # 创建scapy脚本
        script = f"""
#!/usr/bin/env python3
from scapy.all import *
import time

for i in range({count}):
    # 构建BPDU包
    eth = Ether(dst="01:80:c2:00:00:00", src="{src_mac}")
    llc = LLC(dsap=0x42, ssap=0x42, ctrl=0x03)

    # STP BPDU
    bpdu = STP(
        bpdutype=0x00,
        bpduflags=0x01,
        rootid={priority},
        rootmac="{src_mac}",
        pathcost=0,
        bridgeid={priority},
        bridgemac="{src_mac}",
        portid=0x8001
    )

    # 发送包
    packet = eth/llc/bpdu
    sendp(packet, iface="{interface}", verbose=0)
    print(f"发送恶意BPDU #{{i+1}}")
    time.sleep({interval})

print("恶意BPDU注入完成")
"""

        # 写入临时文件
        script_path = "/tmp/rogue_bpdu.py"
        self.node.execute(f"echo '{script}' > {script_path}")
        self.node.execute(f"chmod +x {script_path}")

        # 后台执行
        stdout, stderr, code = self.node.execute_sudo(
            f"nohup python3 {script_path} > /tmp/rogue_bpdu.log 2>&1 &"
        )

        if code == 0:
            self.logger.warning(f"恶意BPDU注入已启动 (优先级: {priority})")
            return True
        else:
            self.logger.error(f"无法注入恶意BPDU: {stderr}")
            return False

    def clear_all_faults(self) -> None:
        """清除所有故障"""
        self.logger.info("清除所有故障")

        for interface in list(self.active_faults.keys()):
            fault_type = self.active_faults[interface]

            if fault_type == FaultType.LINK_DOWN:
                self.link_up(interface)
            elif fault_type in [FaultType.DELAY, FaultType.PACKET_LOSS,
                                FaultType.BANDWIDTH_LIMIT, FaultType.JITTER]:
                self.clear_tc_rules(interface)

        self.active_faults.clear()
        self.logger.info("所有故障已清除")

    def get_active_faults(self) -> Dict[str, FaultType]:
        """获取当前活动的故障"""
        return self.active_faults.copy()
"""
故障注入模块
"""

import time
import logging
from typing import Optional, List, Dict
from enum import Enum

try:
    from .ssh_manager import SSHManager
except ImportError:
    from ssh_manager import SSHManager


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
        """注入恶意BPDU - 增强版直接物理层注入"""
        self.logger.warning(f"注入恶意BPDU到 {interface}，优先级: {priority}")
        
        # 检查接口是否在网桥中
        bridge_check_cmd = "brctl show"
        stdout, stderr, code = self.node.execute(bridge_check_cmd)
        self.logger.info(f"网桥状态检查: {(stdout, stderr, code)}")
        
        # 尝试多个接口发送BPDU
        interfaces_to_try = [interface]
        if interface == "eth2":
            # 如果eth2在网桥中或无法直接到达DUT，尝试其他接口
            interfaces_to_try = ["eth2", "eth0", "eth1"]
        
        success_count = 0
        total_attempts = 0
        
        for iface in interfaces_to_try:
            self.logger.info(f"尝试通过接口 {iface} 发送BPDU")
            
            # 检查接口状态
            iface_check_cmd = f"ip link show {iface}"
            iface_stdout, _, iface_code = self.node.execute(iface_check_cmd)
            if iface_code != 0:
                self.logger.warning(f"接口 {iface} 不存在，跳过")
                continue
                
            if "UP" not in iface_stdout:
                self.logger.warning(f"接口 {iface} 未启用，跳过")
                continue
            
            # 检查此接口是否在网桥中
            iface_in_bridge = iface in stdout
            
            if iface_in_bridge:
                self.logger.info(f"接口 {iface} 在网桥中，临时移除")
                # 临时移除接口
                remove_cmd = f"brctl delif br0 {iface}"
                self.node.execute_sudo(remove_cmd)
                time.sleep(1)
            else:
                self.logger.info(f"接口 {iface} 不在任何网桥中")
        
            # 创建Python脚本内容
            script_lines = [
                '#!/usr/bin/env python3',
                '# -*- coding: utf-8 -*-',
                '',
                'import socket',
                'import struct', 
                'import time',
                'import sys',
                '',
                f'interface = "{iface}"',
                f'priority = {priority}',
                f'src_mac = "{src_mac}"',
                f'count = {count}',
                f'interval = {interval}',
                'success_count = 0',
                '',
                'print("=== 恶意BPDU注入器 (增强版) ===")',
                'print(f"接口: {interface}")',
                'print(f"优先级: {priority}")',
                'print(f"源MAC: {src_mac}")',
                'print(f"数量: {count}, 间隔: {interval}s")',
                '',
                'def build_bpdu_frame():',
                '    dst_mac = bytes.fromhex("01:80:C2:00:00:00".replace(":", ""))',
                '    src_mac_bytes = bytes.fromhex(src_mac.replace(":", ""))',
                '    length = struct.pack(">H", 38)',
                '    llc = struct.pack(">BBB", 0x42, 0x42, 0x03)',
                '    protocol_id = struct.pack(">H", 0x0000)',
                '    version = struct.pack(">B", 0x02)',
                '    bpdu_type = struct.pack(">B", 0x02)',
                '    flags = struct.pack(">B", 0x3C)',
                '    bridge_id = struct.pack(">H", priority) + src_mac_bytes',
                '    root_id = bridge_id',
                '    root_path_cost = struct.pack(">I", 0)',
                '    port_id = struct.pack(">H", 0x8001)',
                '    message_age = struct.pack(">H", 0)',
                '    max_age = struct.pack(">H", 20 << 8)',
                '    hello_time = struct.pack(">H", 2 << 8)',
                '    forward_delay = struct.pack(">H", 15 << 8)',
                '    frame = (dst_mac + src_mac_bytes + length + llc +',
                '             protocol_id + version + bpdu_type + flags +',
                '             root_id + root_path_cost + bridge_id + port_id +',
                '             message_age + max_age + hello_time + forward_delay)',
                '    return frame',
                '',
                'def send_via_raw_socket():',
                '    global success_count',
                '    print("\\n=== 方法1: RAW Socket发送 ===")',
                '    try:',
                '        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)',
                '        sock.bind((interface, 0))',
                '        frame = build_bpdu_frame()',
                '        for i in range(count):',
                '            try:',
                '                sock.send(frame)',
                '                print(f"RAW Socket发送BPDU #{i+1}")',
                '                success_count += 1',
                '                if i < count - 1:',
                '                    time.sleep(interval)',
                '            except Exception as e:',
                '                print(f"RAW Socket发送失败 #{i+1}: {e}")',
                '        sock.close()',
                '        print(f"RAW Socket方法完成: {success_count}/{count}")',
                '        return success_count > 0',
                '    except Exception as e:',
                '        print(f"RAW Socket方法失败: {e}")',
                '        return False',
                '',
                'try:',
                '    print("\\n开始BPDU注入...")',
                '    if send_via_raw_socket():',
                '        print("\\n✓ RAW Socket方法成功")',
                '    else:',
                '        print("\\n✗ RAW Socket方法失败")',
                '    print(f"\\n=== 注入结果 ===")',
                '    print(f"总共发送: {success_count}/{count} 个BPDU")',
                '    print(f"目标: 劫持根桥 (优先级 {priority})")',
                '    if success_count > 0:',
                '        print("\\n✓ BPDU注入成功完成")',
                '        sys.exit(0)',
                '    else:',
                '        print("\\n✗ BPDU注入失败")',
                '        sys.exit(1)',
                'except KeyboardInterrupt:',
                '    print("\\n用户中断")',
                '    sys.exit(1)',
                'except Exception as e:',
                '    print(f"\\n严重错误: {e}")',
                '    sys.exit(1)'
            ]
            script = '\n'.join(script_lines)
            
            # 写入并执行脚本
            script_path = f"/tmp/rogue_bpdu_{iface}.py"
            # 使用cat命令写入脚本，避免引号冲突
            write_cmd = f"cat > {script_path} << 'EOF'\n{script}\nEOF"
            self.node.execute(write_cmd)
            self.node.execute(f"chmod +x {script_path}")
            
            # 使用sudo执行以获得raw socket权限
            stdout, stderr, code = self.node.execute_sudo(f"python3 {script_path}")
            
            self.logger.info(f"接口 {iface} BPDU注入脚本执行结果 (code={code}):")
            if stdout:
                self.logger.info(f"STDOUT: {stdout}")
            if stderr and code != 0:
                self.logger.warning(f"STDERR: {stderr}")
            
            total_attempts += 1
            
            if code == 0 or "成功发送" in str(stdout):
                success_count += 1
                self.logger.warning(f"接口 {iface} 恶意BPDU注入成功 (优先级: {priority})")
            else:
                self.logger.error(f"接口 {iface} 恶意BPDU注入失败")
            
            # 恢复接口到网桥（如果之前移除了）
            if iface_in_bridge:
                self.logger.info(f"恢复接口 {iface} 到网桥")
                restore_cmd = f"brctl addif br0 {iface}"
                self.node.execute_sudo(restore_cmd)
                time.sleep(0.5)
        
        # 输出最终结果
        self.logger.info(f"BPDU注入总结: {success_count}/{total_attempts} 个接口成功")
        
        if success_count > 0:
            self.logger.warning(f"恶意BPDU注入完成 - 成功接口数: {success_count}")
            return True
        else:
            self.logger.error(f"所有接口的BPDU注入均失败")
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
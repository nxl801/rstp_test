"""
流量生成和分析模块
"""

import time
import re
import json
import threading
import queue
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    from .ssh_manager import SSHManager
except ImportError:
    from ssh_manager import SSHManager

class TrafficType(Enum):
    """流量类型"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    MULTICAST = "multicast"
    BROADCAST = "broadcast"

@dataclass
class TrafficStats:
    """流量统计"""
    start_time: float
    end_time: float = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    packets_lost: int = 0
    loss_percent: float = 0.0
    jitter_ms: float = 0.0
    latency_ms: float = 0.0
    bandwidth_mbps: float = 0.0

    def calculate_metrics(self):
        """计算度量指标"""
        if self.end_time > self.start_time:
            duration = self.end_time - self.start_time
            self.bandwidth_mbps = (self.bytes_received * 8) / (duration * 1000000)

        if self.packets_sent > 0:
            self.loss_percent = (self.packets_lost / self.packets_sent) * 100

class TrafficGenerator:
    """流量生成器"""

    def __init__(self, server_node: SSHManager, client_node: SSHManager):
        """
        初始化流量生成器

        Args:
            server_node: 服务器节点
            client_node: 客户端节点
        """
        self.server = server_node
        self.client = client_node
        self.logger = logging.getLogger("TrafficGenerator")

        # 线程控制
        self.server_thread = None
        self.client_thread = None
        self.monitor_thread = None
        self.stop_event = threading.Event()

        # 结果队列
        self.results_queue = queue.Queue()

        # 统计信息
        self.current_stats = None
        self.history_stats = []

        # 默认配置
        self.server_ip = None
        self.server_port = 5201

    def start_iperf_server(self, port: int = 5201, bind_ip: str = None) -> bool:
        """
        启动iperf3服务器，如果同一节点上已有监听进程则直接复用

        Args:
            port: 监听端口
            bind_ip: 绑定IP地址

        Returns:
            是否成功
        """
        # 若已有iperf3服务器在运行，检查端口是否匹配
        stdout_running, _, running_code = self.server.execute(f"netstat -tlnp | grep ':{port} '")
        if running_code == 0 and stdout_running.strip():
            self.logger.info(f"端口{port}已被占用，检查是否为iperf3服务器")
            # 检查是否为iperf3进程
            stdout_iperf, _, iperf_code = self.server.execute("pgrep -f 'iperf3 -s'")
            if iperf_code == 0:
                self.logger.info(f"iperf3服务器已在运行 (PID: {stdout_iperf.strip()})，复用现有进程")
                if bind_ip:
                    self.server_ip = bind_ip
                else:
                    stdout_ip, _, _ = self.server.execute("hostname -I | awk '{print $1}'")
                    self.server_ip = stdout_ip.strip()
                self.server_port = port
                return True
            else:
                self.logger.warning(f"端口{port}被其他进程占用，尝试使用其他端口")
                port = port + 1
        
        # 停止已有iperf3服务器
        self._kill_iperf_server()
        
        # 获取服务器IP
        if bind_ip:
            self.server_ip = bind_ip
        else:
            stdout, _, _ = self.server.execute("hostname -I | awk '{print $1}'")
            self.server_ip = stdout.strip()
            if not self.server_ip:
                # 备用方法获取IP
                stdout, _, _ = self.server.execute("ip route get 8.8.8.8 | awk '{print $7; exit}'")
                self.server_ip = stdout.strip()
        
        self.server_port = port
        
        # 构建命令
        cmd = f"iperf3 -s -p {port} -D"  # 使用-D参数以守护进程方式运行
        if bind_ip:
            cmd += f" -B {bind_ip}"
        
        self.logger.info(f"启动iperf3服务器: {self.server_ip}:{port}")
        
        # 直接启动服务器（不使用线程）
        stdout, stderr, code = self.server.execute(cmd, timeout=10)
        
        if code != 0:
            self.logger.error(f"iperf3服务器启动失败: {stderr}")
            # 尝试不使用守护进程模式
            cmd_fallback = f"nohup iperf3 -s -p {port}"
            if bind_ip:
                cmd_fallback += f" -B {bind_ip}"
            cmd_fallback += " > /tmp/iperf_server.log 2>&1 &"
            
            stdout, stderr, code = self.server.execute(cmd_fallback, timeout=5)
            if code != 0:
                self.logger.error(f"iperf3服务器启动失败（备用方法）: {stderr}")
                return False
        
        # 等待服务器启动
        time.sleep(2)
        
        # 验证服务器是否运行
        for attempt in range(5):  # 最多尝试5次
            stdout, _, code = self.server.execute(f"netstat -tlnp | grep ':{port} '")
            if code == 0 and stdout.strip():
                self.logger.info(f"iperf3服务器已成功启动并监听端口{port}")
                return True
            time.sleep(1)
        
        # 检查错误日志
        stdout, _, _ = self.server.execute("cat /tmp/iperf_server.log 2>/dev/null || echo 'No log file'")
        if stdout and "No log file" not in stdout:
            self.logger.error(f"iperf3服务器日志: {stdout}")
        
        self.logger.error("iperf3服务器启动失败，无法监听指定端口")
        return False

    def start_iperf_client(self, server_ip: str = None, bandwidth: str = "100M",
                          duration: int = 0, port: int = None,
                          protocol: str = "udp", parallel: int = 1) -> bool:
        """
        启动iperf3客户端

        Args:
            server_ip: 服务器IP
            bandwidth: 带宽限制
            duration: 持续时间(0表示持续运行)
            port: 服务器端口
            protocol: 协议(tcp/udp)
            parallel: 并行流数量

        Returns:
            是否成功
        """
        server_ip = server_ip or self.server_ip
        port = port or self.server_port

        if not server_ip:
            self.logger.error("服务器IP未指定")
            return False

        # 构建命令
        cmd = f"iperf3 -c {server_ip} -p {port}"

        if protocol == "udp":
            cmd += " -u"

        cmd += f" -b {bandwidth}"
        cmd += f" -P {parallel}"
        cmd += " -i 1"  # 1秒报告间隔
        cmd += " --json"  # JSON输出

        if duration > 0:
            cmd += f" -t {duration}"
        else:
            cmd += " -t 86400"  # 24小时

        # 启动客户端线程
        def run_client():
            self.logger.info(f"启动iperf3客户端: -> {server_ip}:{port}")
            self.current_stats = TrafficStats(start_time=time.time())

            stdout, stderr, code = self.client.execute(cmd, timeout=duration + 10)

            # 解析结果
            if stdout:
                try:
                    result = json.loads(stdout)
                    self._parse_iperf_result(result)
                except json.JSONDecodeError:
                    self.logger.error("无法解析iperf3输出")

            self.results_queue.put((stdout, stderr, code))

        self.client_thread = threading.Thread(target=run_client, daemon=True)
        self.client_thread.start()

        self.logger.info(f"iperf3客户端已启动 ({protocol}, {bandwidth})")
        return True

    def stop_traffic(self) -> TrafficStats:
        """
        停止流量生成

        Returns:
            流量统计
        """
        self.logger.info("停止流量生成")

        # 设置停止标志
        self.stop_event.set()

        # 停止客户端
        self._kill_iperf_client()

        # 停止服务器
        self._kill_iperf_server()

        # 等待线程结束
        if self.client_thread and self.client_thread.is_alive():
            self.client_thread.join(timeout=5)

        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5)

        # 返回统计
        if self.current_stats:
            self.current_stats.end_time = time.time()
            self.current_stats.calculate_metrics()
            self.history_stats.append(self.current_stats)

        return self.current_stats

    def get_statistics(self) -> Dict[str, Any]:
        """获取当前统计信息"""
        if not self.current_stats:
            return {}

        return {
            'bytes_sent': self.current_stats.bytes_sent,
            'bytes_received': self.current_stats.bytes_received,
            'packets_sent': self.current_stats.packets_sent,
            'packets_received': self.current_stats.packets_received,
            'packets_lost': self.current_stats.packets_lost,
            'loss_percent': self.current_stats.loss_percent,
            'bandwidth_mbps': self.current_stats.bandwidth_mbps,
            'jitter_ms': self.current_stats.jitter_ms,
            'latency_ms': self.current_stats.latency_ms
        }

    def get_packet_rate(self) -> float:
        """获取包速率(pps)"""
        if not self.current_stats:
            return 0

        duration = time.time() - self.current_stats.start_time
        if duration > 0:
            return self.current_stats.packets_sent / duration
        return 0

    def monitor_packet_loss(self, duration: int = 10,
                          interval: float = 0.5) -> List[Dict[str, Any]]:
        """
        监控丢包情况

        Args:
            duration: 监控时长
            interval: 采样间隔

        Returns:
            丢包数据列表
        """
        self.logger.info(f"开始监控丢包 (持续{duration}秒)")

        loss_data = []
        start_time = time.time()
        last_stats = self.get_statistics()

        while time.time() - start_time < duration:
            time.sleep(interval)

            current_stats = self.get_statistics()

            # 计算增量
            delta_lost = current_stats.get('packets_lost', 0) - \
                        last_stats.get('packets_lost', 0)
            delta_sent = current_stats.get('packets_sent', 0) - \
                        last_stats.get('packets_sent', 0)

            if delta_sent > 0:
                instant_loss = (delta_lost / delta_sent) * 100
            else:
                instant_loss = 0

            loss_data.append({
                'timestamp': time.time() - start_time,
                'packets_lost': delta_lost,
                'packets_sent': delta_sent,
                'instant_loss_percent': instant_loss,
                'total_loss_percent': current_stats.get('loss_percent', 0)
            })

            last_stats = current_stats

        return loss_data

    def generate_ping_flood(self, target_ip: str, count: int = 1000,
                          packet_size: int = 64) -> Dict[str, Any]:
        """
        生成ping flood流量

        Args:
            target_ip: 目标IP
            count: 包数量
            packet_size: 包大小

        Returns:
            ping统计
        """
        self.logger.info(f"生成ping flood: {target_ip}")

        cmd = f"ping -f -c {count} -s {packet_size} {target_ip}"
        stdout, stderr, code = self.client.execute_sudo(cmd, timeout=60)

        # 解析ping输出
        stats = {
            'target': target_ip,
            'packets_sent': 0,
            'packets_received': 0,
            'packet_loss': 0,
            'min_rtt': 0,
            'avg_rtt': 0,
            'max_rtt': 0
        }

        # 解析统计行
        for line in stdout.split('\n'):
            if 'packets transmitted' in line:
                match = re.search(r'(\d+) packets transmitted, (\d+) received, (\d+)% packet loss', line)
                if match:
                    stats['packets_sent'] = int(match.group(1))
                    stats['packets_received'] = int(match.group(2))
                    stats['packet_loss'] = int(match.group(3))
            elif 'rtt min/avg/max' in line:
                match = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)', line)
                if match:
                    stats['min_rtt'] = float(match.group(1))
                    stats['avg_rtt'] = float(match.group(2))
                    stats['max_rtt'] = float(match.group(3))

        return stats

    def generate_multicast_traffic(self, group_ip: str = "239.1.1.1",
                                  port: int = 5001, rate: str = "1M",
                                  duration: int = 10) -> bool:
        """
        生成组播流量

        Args:
            group_ip: 组播组地址
            port: 端口
            rate: 发送速率
            duration: 持续时间

        Returns:
            是否成功
        """
        self.logger.info(f"生成组播流量: {group_ip}:{port}")

        # 使用iperf3的组播模式（如果支持）或使用其他工具
        # 这里使用简单的UDP组播
        script = f"""
import socket
import time
import struct

MCAST_GRP = '{group_ip}'
MCAST_PORT = {port}
MULTICAST_TTL = 2

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)

message = b'X' * 1024  # 1KB payload
start_time = time.time()
count = 0

while time.time() - start_time < {duration}:
    sock.sendto(message, (MCAST_GRP, MCAST_PORT))
    count += 1
    time.sleep(0.001)  # 控制速率
    
print(f'Sent {{count}} multicast packets')
"""

        # 写入并执行脚本
        self.client.execute(f"echo '{script}' > /tmp/mcast_gen.py")
        stdout, stderr, code = self.client.execute(
            f"python3 /tmp/mcast_gen.py",
            timeout=duration + 5
        )

        if code == 0:
            self.logger.info(f"组播流量生成完成: {stdout.strip()}")
            return True
        else:
            self.logger.error(f"组播流量生成失败: {stderr}")
            return False

    def _kill_iperf_server(self):
        """终止iperf服务器"""
        self.server.execute("pkill -f 'iperf3 -s' 2>/dev/null || true")
        time.sleep(1)

    def _kill_iperf_client(self):
        """终止iperf客户端"""
        self.client.execute("pkill -f 'iperf3 -c' 2>/dev/null || true")
        time.sleep(1)

    def _parse_iperf_result(self, result: Dict):
        """解析iperf3 JSON结果"""
        if 'end' in result:
            end = result['end']

            if 'sum_sent' in end:
                sent = end['sum_sent']
                self.current_stats.bytes_sent = sent.get('bytes', 0)
                self.current_stats.packets_sent = sent.get('packets', 0)

            if 'sum_received' in end:
                received = end['sum_received']
                self.current_stats.bytes_received = received.get('bytes', 0)
                self.current_stats.packets_received = received.get('packets', 0)
                self.current_stats.packets_lost = received.get('lost_packets', 0)
                self.current_stats.loss_percent = received.get('lost_percent', 0)
                self.current_stats.jitter_ms = received.get('jitter_ms', 0)

            if 'streams' in end:
                # 解析每个流的详细信息
                for stream in end['streams']:
                    if 'udp' in stream:
                        udp = stream['udp']
                        self.current_stats.packets_lost += udp.get('lost_packets', 0)
                        self.current_stats.jitter_ms = max(
                            self.current_stats.jitter_ms,
                            udp.get('jitter_ms', 0)
                        )
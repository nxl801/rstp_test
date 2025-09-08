"""
SSH连接管理模块
"""

import time
import logging
from typing import Tuple, Optional
from dataclasses import dataclass

import paramiko
from paramiko import SSHClient, AutoAddPolicy


@dataclass
class SSHConfig:
    """SSH配置"""
    name: str
    ip: str
    username: str
    password: str
    port: int = 22
    timeout: int = 30


class SSHManager:
    """SSH连接管理器"""

    def __init__(self, name: str, ip: str, username: str, password: str, port: int = 22):
        self.config = SSHConfig(name, ip, username, password, port)
        self.client: Optional[SSHClient] = None
        self.logger = logging.getLogger(f"SSH_{name}")

    def connect(self, retry: int = 3) -> bool:
        """建立SSH连接"""
        for attempt in range(retry):
            try:
                self.client = SSHClient()
                self.client.set_missing_host_key_policy(AutoAddPolicy())
                self.client.connect(
                    hostname=self.config.ip,
                    port=self.config.port,
                    username=self.config.username,
                    password=self.config.password,
                    timeout=self.config.timeout,
                    look_for_keys=False,
                    allow_agent=False,
                    banner_timeout=30
                )
                self.logger.info(f"SSH连接成功: {self.config.name} ({self.config.ip})")
                return True
            except Exception as e:
                self.logger.warning(
                    f"SSH连接失败 [{self.config.name}] "
                    f"(尝试 {attempt + 1}/{retry}): {e}"
                )
                if attempt < retry - 1:
                    time.sleep(5)

        self.logger.error(f"无法连接到 {self.config.name}")
        return False

    def execute(self, command: str, timeout: int = 30,
                get_pty: bool = False) -> Tuple[str, str, int]:
        """执行SSH命令"""
        if not self.client:
            if not self.connect():
                raise ConnectionError(f"无法连接到 {self.config.name}")

        try:
            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=timeout,
                get_pty=get_pty
            )
            exit_status = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode('utf-8', errors='ignore')
            stderr_data = stderr.read().decode('utf-8', errors='ignore')

            self.logger.debug(
                f"执行命令 [{self.config.name}]: {command[:50]}... "
                f"退出码: {exit_status}"
            )

            return stdout_data, stderr_data, exit_status

        except Exception as e:
            self.logger.error(f"命令执行失败 [{self.config.name}]: {command}\n错误: {e}")
            raise

    def execute_sudo(self, command: str, timeout: int = 30) -> Tuple[str, str, int]:
        """执行需要sudo权限的命令"""
        if not self.client:
            if not self.connect():
                raise ConnectionError(f"无法连接到 {self.config.name}")

        if not command.startswith("sudo"):
            command = f"sudo {command}"

        try:
            # 使用get_pty=True来处理交互式命令
            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=timeout,
                get_pty=True
            )
            
            # 发送密码以处理sudo认证
            stdin.write(f"{self.config.password}\n")
            stdin.flush()
            
            exit_status = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode('utf-8', errors='ignore')
            stderr_data = stderr.read().decode('utf-8', errors='ignore')

            self.logger.debug(
                f"执行sudo命令 [{self.config.name}]: {command[:50]}... "
                f"退出码: {exit_status}"
            )

            return stdout_data, stderr_data, exit_status

        except Exception as e:
            self.logger.error(f"sudo命令执行失败 [{self.config.name}]: {command}\n错误: {e}")
            raise

    def execute_as_root(self, command: str, timeout: int = 30) -> Tuple[str, str, int]:
        """以root用户身份执行命令（适用于DUT设备）"""
        # 直接复用 execute_sudo 逻辑，避免 su 交互卡顿
        return self.execute_sudo(command, timeout)

    def is_connected(self) -> bool:
        """检查连接状态"""
        if not self.client:
            return False
        try:
            transport = self.client.get_transport()
            if transport and transport.is_active():
                # 发送一个测试命令
                self.execute("echo test", timeout=5)
                return True
        except:
            pass
        return False

    def close(self):
        """关闭SSH连接"""
        if self.client:
            try:
                self.client.close()
                self.logger.info(f"SSH连接已关闭: {self.config.name}")
            except:
                pass
            finally:
                self.client = None

    def __enter__(self):
        """上下文管理器入口"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.close()
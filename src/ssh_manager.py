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
        # 如果已有连接，先关闭
        if self.client:
            try:
                self.client.close()
            except:
                pass
            self.client = None
            
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
                if self.client:
                    try:
                        self.client.close()
                    except:
                        pass
                    self.client = None
                if attempt < retry - 1:
                    time.sleep(5)

        self.logger.error(f"无法连接到 {self.config.name}")
        return False

    def execute(self, command: str, timeout: int = 30,
                get_pty: bool = False) -> Tuple[str, str, int]:
        """执行SSH命令"""
        # 检查连接状态，如果断开则尝试重连
        if not self.is_connected():
            self.logger.warning(f"{self.config.name}: SSH连接已断开，尝试重连...")
            try:
                self.connect()
                if not self.is_connected():
                    raise ConnectionError(f"{self.config.name}: SSH重连失败")
                self.logger.info(f"{self.config.name}: SSH重连成功")
            except Exception as e:
                self.logger.error(f"{self.config.name}: SSH重连异常: {e}")
                raise ConnectionError(f"{self.config.name}: SSH连接不可用: {e}")

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
            # 如果是连接相关错误，标记连接为断开状态
            if "SSH session not active" in str(e) or "Socket is closed" in str(e):
                self.logger.warning(f"{self.config.name}: 检测到SSH会话失效，标记连接为断开")
                if self.client:
                    try:
                        self.client.close()
                    except:
                        pass
                    self.client = None
            raise

    def execute_sudo(self, command: str, timeout: int = 30) -> Tuple[str, str, int]:
        """执行需要sudo权限的命令"""
        # 检查连接状态，如果断开则尝试重连
        if not self.is_connected():
            self.logger.warning(f"{self.config.name}: SSH连接已断开，尝试重连...")
            try:
                self.connect()
                if not self.is_connected():
                    raise ConnectionError(f"{self.config.name}: SSH重连失败")
                self.logger.info(f"{self.config.name}: SSH重连成功")
            except Exception as e:
                self.logger.error(f"{self.config.name}: SSH重连异常: {e}")
                raise ConnectionError(f"{self.config.name}: SSH连接不可用: {e}")
        
        try:
            # 使用pty执行sudo命令
            stdin, stdout, stderr = self.client.exec_command(
                f"sudo -S {command}", 
                get_pty=True,
                timeout=timeout
            )
            
            # 发送密码
            stdin.write(f"{self.config.password}\n")
            stdin.flush()
            
            # 读取输出
            stdout_data = stdout.read().decode('utf-8', errors='ignore')
            stderr_data = stderr.read().decode('utf-8', errors='ignore')
            exit_code = stdout.channel.recv_exit_status()
            
            return stdout_data, stderr_data, exit_code
            
        except Exception as e:
            self.logger.error(f"{self.config.name}: 执行sudo命令失败: {e}")
            # 如果是连接相关错误，标记连接为断开状态
            if "SSH session not active" in str(e) or "Socket is closed" in str(e):
                self.logger.warning(f"{self.config.name}: 检测到SSH会话失效，标记连接为断开")
                if self.client:
                    try:
                        self.client.close()
                    except:
                        pass
                    self.client = None
            return "", str(e), 1

    def execute_as_root(self, command: str, timeout: int = 30) -> Tuple[str, str, int]:
        """以root权限执行命令（复用sudo逻辑）"""
        # 检查连接状态，如果断开则尝试重连
        if not self.is_connected():
            self.logger.warning(f"{self.config.name}: SSH连接已断开，尝试重连...")
            try:
                self.connect()
                if not self.is_connected():
                    raise ConnectionError(f"{self.config.name}: SSH重连失败")
                self.logger.info(f"{self.config.name}: SSH重连成功")
            except Exception as e:
                self.logger.error(f"{self.config.name}: SSH重连异常: {e}")
                raise ConnectionError(f"{self.config.name}: SSH连接不可用: {e}")
        
        return self.execute_sudo(command, timeout)

    def is_connected(self) -> bool:
        """检查连接状态"""
        if not self.client:
            return False
        try:
            transport = self.client.get_transport()
            if transport and transport.is_active():
                # 发送一个轻量级测试命令，避免递归调用
                stdin, stdout, stderr = self.client.exec_command("echo test", timeout=5)
                stdout.read()
                return True
        except Exception as e:
            self.logger.debug(f"{self.config.name}: 连接状态检查失败: {e}")
            # 清理无效连接
            if self.client:
                try:
                    self.client.close()
                except:
                    pass
                self.client = None
        return False

    def reconnect(self) -> bool:
        """重新连接SSH"""
        self.logger.info(f"{self.config.name}: 尝试重新建立SSH连接...")
        self.close()
        return self.connect()
    
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
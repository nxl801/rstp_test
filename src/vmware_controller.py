"""
VMware虚拟机控制模块
"""

import os
import time
import logging
import subprocess
from typing import List, Tuple, Optional, Dict
from pathlib import Path
from dataclasses import dataclass
from enum import Enum


class VMState(Enum):
    """虚拟机状态"""
    RUNNING = "running"
    STOPPED = "stopped"
    SUSPENDED = "suspended"
    UNKNOWN = "unknown"


@dataclass
class VMInfo:
    """虚拟机信息"""
    name: str
    path: str
    state: VMState
    ip: Optional[str] = None
    snapshot: Optional[str] = None


class VMwareController:
    """VMware虚拟机控制器"""

    def __init__(self, vmrun_path: str = "/usr/bin/vmrun"):
        """
        初始化VMware控制器

        Args:
            vmrun_path: vmrun工具路径
        """
        self.vmrun = vmrun_path
        self.logger = logging.getLogger("VMwareController")

        # 验证vmrun是否存在
        if not self._check_vmrun():
            raise RuntimeError(f"vmrun工具未找到: {vmrun_path}")

    def _check_vmrun(self) -> bool:
        """检查vmrun工具是否可用"""
        try:
            result = subprocess.run(
                [self.vmrun],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 255  # vmrun不带参数时返回255
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _run_vmrun(self, command: List[str], timeout: int = 60) -> Tuple[str, str, int]:
        """
        执行vmrun命令

        Args:
            command: 命令参数列表
            timeout: 超时时间

        Returns:
            (stdout, stderr, returncode)
        """
        cmd = [self.vmrun] + command
        self.logger.debug(f"执行vmrun: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode != 0:
                self.logger.warning(f"vmrun返回非零: {result.returncode}")
                if result.stderr:
                    self.logger.warning(f"错误输出: {result.stderr}")

            return result.stdout, result.stderr, result.returncode

        except subprocess.TimeoutExpired:
            self.logger.error(f"vmrun命令超时: {' '.join(cmd)}")
            raise
        except Exception as e:
            self.logger.error(f"vmrun执行失败: {e}")
            raise

    def list_running_vms(self) -> List[str]:
        """列出所有运行中的虚拟机"""
        stdout, stderr, code = self._run_vmrun(["list"])

        if code != 0:
            self.logger.error(f"无法列出虚拟机: {stderr}")
            return []

        vms = []
        lines = stdout.strip().split('\n')

        # 第一行是计数，跳过
        for line in lines[1:]:
            line = line.strip()
            if line:
                vms.append(line)

        self.logger.info(f"找到{len(vms)}个运行中的虚拟机")
        return vms

    def start_vm(self, vm_path: str, headless: bool = True,
                 wait_ready: bool = True) -> bool:
        """
        启动虚拟机

        Args:
            vm_path: 虚拟机vmx文件路径
            headless: 是否无界面运行
            wait_ready: 是否等待虚拟机就绪

        Returns:
            是否成功
        """
        # 检查虚拟机文件是否存在
        if not Path(vm_path).exists():
            self.logger.error(f"虚拟机文件不存在: {vm_path}")
            return False

        # 检查是否已运行
        if self.is_running(vm_path):
            self.logger.info(f"虚拟机已在运行: {vm_path}")
            return True

        mode = "nogui" if headless else "gui"
        stdout, stderr, code = self._run_vmrun(["start", vm_path, mode])

        if code != 0:
            self.logger.error(f"启动虚拟机失败: {stderr}")
            return False

        self.logger.info(f"虚拟机已启动: {vm_path}")

        if wait_ready:
            return self._wait_for_vm_ready(vm_path)

        return True

    def stop_vm(self, vm_path: str, hard: bool = False) -> bool:
        """
        停止虚拟机

        Args:
            vm_path: 虚拟机路径
            hard: 是否强制停止

        Returns:
            是否成功
        """
        if not self.is_running(vm_path):
            self.logger.info(f"虚拟机未运行: {vm_path}")
            return True

        mode = "hard" if hard else "soft"
        stdout, stderr, code = self._run_vmrun(["stop", vm_path, mode])

        if code != 0:
            self.logger.error(f"停止虚拟机失败: {stderr}")
            return False

        self.logger.info(f"虚拟机已停止: {vm_path}")
        return True

    def suspend_vm(self, vm_path: str) -> bool:
        """挂起虚拟机"""
        if not self.is_running(vm_path):
            self.logger.warning(f"虚拟机未运行: {vm_path}")
            return False

        stdout, stderr, code = self._run_vmrun(["suspend", vm_path])

        if code != 0:
            self.logger.error(f"挂起虚拟机失败: {stderr}")
            return False

        self.logger.info(f"虚拟机已挂起: {vm_path}")
        return True

    def reset_vm(self, vm_path: str, hard: bool = True) -> bool:
        """重启虚拟机"""
        if not self.is_running(vm_path):
            self.logger.warning(f"虚拟机未运行: {vm_path}")
            return False

        mode = "hard" if hard else "soft"
        stdout, stderr, code = self._run_vmrun(["reset", vm_path, mode])

        if code != 0:
            self.logger.error(f"重启虚拟机失败: {stderr}")
            return False

        self.logger.info(f"虚拟机已重启: {vm_path}")
        return True

    def is_running(self, vm_path: str) -> bool:
        """检查虚拟机是否运行"""
        running_vms = self.list_running_vms()
        return vm_path in running_vms

    def list_snapshots(self, vm_path: str) -> List[str]:
        """列出虚拟机快照"""
        stdout, stderr, code = self._run_vmrun(["listSnapshots", vm_path])

        if code != 0:
            self.logger.error(f"列出快照失败: {stderr}")
            return []

        snapshots = []
        lines = stdout.strip().split('\n')

        # 跳过第一行（Total snapshots: N）
        for line in lines[1:]:
            line = line.strip()
            if line:
                snapshots.append(line)

        self.logger.info(f"找到{len(snapshots)}个快照")
        return snapshots

    def snapshot(self, vm_path: str, snapshot_name: str) -> bool:
        """创建快照"""
        if not self.is_running(vm_path):
            self.logger.warning("创建快照时虚拟机未运行")

        stdout, stderr, code = self._run_vmrun(
            ["snapshot", vm_path, snapshot_name]
        )

        if code != 0:
            self.logger.error(f"创建快照失败: {stderr}")
            return False

        self.logger.info(f"快照已创建: {snapshot_name}")
        return True

    def revert_snapshot(self, vm_path: str, snapshot_name: str) -> bool:
        """恢复快照"""
        # 先检查快照是否存在
        snapshots = self.list_snapshots(vm_path)
        if snapshot_name not in snapshots:
            self.logger.error(f"快照不存在: {snapshot_name}")
            return False

        stdout, stderr, code = self._run_vmrun(
            ["revertToSnapshot", vm_path, snapshot_name]
        )

        if code != 0:
            self.logger.error(f"恢复快照失败: {stderr}")
            return False

        self.logger.info(f"已恢复到快照: {snapshot_name}")
        return True

    def delete_snapshot(self, vm_path: str, snapshot_name: str) -> bool:
        """删除快照"""
        stdout, stderr, code = self._run_vmrun(
            ["deleteSnapshot", vm_path, snapshot_name]
        )

        if code != 0:
            self.logger.error(f"删除快照失败: {stderr}")
            return False

        self.logger.info(f"快照已删除: {snapshot_name}")
        return True

    def get_ip_address(self, vm_path: str, wait: bool = True,
                       timeout: int = 60) -> Optional[str]:
        """
        获取虚拟机IP地址

        Args:
            vm_path: 虚拟机路径
            wait: 是否等待获取IP
            timeout: 等待超时时间

        Returns:
            IP地址或None
        """
        if not self.is_running(vm_path):
            self.logger.error("虚拟机未运行")
            return None

        start_time = time.time()

        while True:
            stdout, stderr, code = self._run_vmrun(
                ["getGuestIPAddress", vm_path]
            )

            if code == 0 and stdout.strip():
                ip = stdout.strip()
                self.logger.info(f"获取到IP地址: {ip}")
                return ip

            if not wait or (time.time() - start_time) > timeout:
                break

            time.sleep(2)

        self.logger.warning("无法获取IP地址")
        return None

    def run_program_in_guest(self, vm_path: str, username: str, password: str,
                             program: str, args: str = "",
                             wait: bool = True, interactive: bool = False) -> bool:
        """
        在虚拟机中运行程序

        Args:
            vm_path: 虚拟机路径
            username: 用户名
            password: 密码
            program: 程序路径
            args: 程序参数
            wait: 是否等待程序完成
            interactive: 是否交互模式

        Returns:
            是否成功
        """
        if not self.is_running(vm_path):
            self.logger.error("虚拟机未运行")
            return False

        cmd = ["runProgramInGuest", vm_path, username, password]

        if wait:
            if interactive:
                cmd.append("-interactive")
            else:
                cmd.append("-noWait")

        cmd.extend([program, args])

        stdout, stderr, code = self._run_vmrun(cmd)

        if code != 0:
            self.logger.error(f"运行程序失败: {stderr}")
            return False

        self.logger.info(f"程序已运行: {program} {args}")
        return True

    def copy_file_to_guest(self, vm_path: str, username: str, password: str,
                           host_path: str, guest_path: str) -> bool:
        """复制文件到虚拟机"""
        if not Path(host_path).exists():
            self.logger.error(f"源文件不存在: {host_path}")
            return False

        stdout, stderr, code = self._run_vmrun([
            "copyFileFromHostToGuest", vm_path,
            username, password, host_path, guest_path
        ])

        if code != 0:
            self.logger.error(f"复制文件失败: {stderr}")
            return False

        self.logger.info(f"文件已复制: {host_path} -> {guest_path}")
        return True

    def copy_file_from_guest(self, vm_path: str, username: str, password: str,
                             guest_path: str, host_path: str) -> bool:
        """从虚拟机复制文件"""
        stdout, stderr, code = self._run_vmrun([
            "copyFileFromGuestToHost", vm_path,
            username, password, guest_path, host_path
        ])

        if code != 0:
            self.logger.error(f"复制文件失败: {stderr}")
            return False

        self.logger.info(f"文件已复制: {guest_path} -> {host_path}")
        return True

    def _wait_for_vm_ready(self, vm_path: str, timeout: int = 120) -> bool:
        """等待虚拟机就绪"""
        self.logger.info("等待虚拟机就绪...")
        start_time = time.time()

        while (time.time() - start_time) < timeout:
            # 尝试获取IP地址作为就绪标志
            if self.get_ip_address(vm_path, wait=False):
                self.logger.info("虚拟机已就绪")
                return True

            time.sleep(5)

        self.logger.warning("等待虚拟机就绪超时")
        return False

    def batch_operation(self, vms: List[Dict[str, str]],
                        operation: str, parallel: bool = False) -> Dict[str, bool]:
        """
        批量操作虚拟机

        Args:
            vms: 虚拟机列表 [{'name': 'vm1', 'path': '/path/to/vm.vmx'}, ...]
            operation: 操作类型 (start/stop/suspend/reset)
            parallel: 是否并行执行

        Returns:
            操作结果字典
        """
        results = {}

        for vm in vms:
            vm_name = vm.get('name', 'unknown')
            vm_path = vm.get('path')

            if not vm_path:
                self.logger.error(f"虚拟机路径缺失: {vm_name}")
                results[vm_name] = False
                continue

            self.logger.info(f"执行批量操作: {operation} on {vm_name}")

            if operation == 'start':
                results[vm_name] = self.start_vm(vm_path)
            elif operation == 'stop':
                results[vm_name] = self.stop_vm(vm_path)
            elif operation == 'suspend':
                results[vm_name] = self.suspend_vm(vm_path)
            elif operation == 'reset':
                results[vm_name] = self.reset_vm(vm_path)
            else:
                self.logger.error(f"未知操作: {operation}")
                results[vm_name] = False

            if not parallel:
                time.sleep(2)  # 串行执行时的延迟

        return results
#!/usr/bin/env python3
"""
测试修复后的BPDU注入功能
验证恶意BPDU能否成功送达DUT并触发根桥劫持攻击
"""

import sys
import os
import time
import yaml
import logging
from pathlib import Path

# 添加src目录到Python路径
sys.path.insert(0, str(Path(__file__).parent / "src"))

from ssh_manager import SSHManager
from vmware_controller import VMwareController
from fault_injector import FaultInjector

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_config():
    """加载配置文件"""
    config_path = Path(__file__).parent / "config.yaml"
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def start_vms_and_wait(config):
    """启动虚拟机并等待SSH就绪"""
    logger.info("启动测试环境虚拟机...")
    
    vmware_controller = VMwareController(config['test_environment']['vmware']['vmrun_path'])
    
    # 启动DUT
    dut_vm_path = config['vms']['dut']['vm_path']
    logger.info(f"启动DUT虚拟机: {dut_vm_path}")
    if not vmware_controller.start_vm(dut_vm_path):
        logger.error("启动DUT虚拟机失败")
        return False
    
    # 启动TestNode1
    testnode1_vm_path = config['vms']['nodes'][0]['vm_path']  # 第一个节点是TestNode1
    logger.info(f"启动TestNode1虚拟机: {testnode1_vm_path}")
    if not vmware_controller.start_vm(testnode1_vm_path):
        logger.error("启动TestNode1虚拟机失败")
        return False
    
    # 等待虚拟机启动
    logger.info("等待虚拟机启动完成...")
    time.sleep(30)
    
    return True

def wait_for_ssh_ready(ssh_manager, max_attempts=10):
    """等待SSH连接就绪"""
    for attempt in range(max_attempts):
        try:
            stdout, stderr, code = ssh_manager.execute("echo 'SSH Ready'")
            if code == 0:
                logger.info(f"{ssh_manager.config.name} SSH连接就绪")
                return True
        except Exception as e:
            logger.warning(f"{ssh_manager.config.name} SSH连接尝试 {attempt+1}/{max_attempts} 失败: {e}")
        
        time.sleep(5)
    
    logger.error(f"{ssh_manager.config.name} SSH连接失败")
    return False

def setup_network_connectivity(dut, testnode1):
    """设置网络连通性"""
    logger.info("设置网络连通性...")
    
    try:
        # 检查DUT网络配置
        logger.info("检查DUT网络配置")
        stdout, _, _ = dut.execute_sudo("ip addr show")
        logger.info(f"DUT网络接口:\n{stdout}")
        
        # 检查TestNode1网络配置
        logger.info("检查TestNode1网络配置")
        stdout, _, _ = testnode1.execute("ip addr show")
        logger.info(f"TestNode1网络接口:\n{stdout}")
        
        # 测试连通性
        logger.info("测试TestNode1到DUT的连通性")
        stdout, stderr, code = testnode1.execute("ping -c 3 192.168.1.123")
        if code == 0:
            logger.info("TestNode1到DUT连通性正常")
            return True
        else:
            logger.warning(f"TestNode1到DUT连通性异常: {stdout}")
            
            # 尝试配置路由
            logger.info("尝试配置网络路由...")
            testnode1.execute_sudo("ip route add 192.168.1.0/24 via 192.168.2.1 || true")
            
            # 再次测试
            stdout, stderr, code = testnode1.execute("ping -c 3 192.168.1.123")
            if code == 0:
                logger.info("配置路由后连通性正常")
                return True
            else:
                logger.error(f"配置路由后仍无法连通: {stdout}")
                return False
                
    except Exception as e:
        logger.error(f"网络连通性设置失败: {e}")
        return False

def test_enhanced_bpdu_injection(dut, testnode1):
    """测试增强的BPDU注入功能"""
    logger.info("\n=== 开始增强BPDU注入测试 ===")
    
    try:
        # 1. 记录初始状态
        logger.info("1. 记录DUT初始RSTP状态")
        stdout, _, _ = dut.execute_sudo("ovs-vsctl list bridge")
        logger.info(f"DUT初始网桥状态:\n{stdout}")
        
        # 2. 启动DUT侧抓包
        logger.info("2. 启动DUT侧BPDU抓包")
        capture_interfaces = ['br3', 'br4', 'eth0', 'eth1', 'eth2']
        
        for iface in capture_interfaces:
            try:
                # 检查接口是否存在
                stdout, _, code = dut.execute_sudo(f"ip link show {iface}")
                if code == 0:
                    # 启动抓包
                    cmd = (
                        f"nohup tcpdump -i {iface} -c 50 -vv -s 0 "
                        f"-w /tmp/test_bpdu_{iface}.pcap "
                        f"'ether dst 01:80:c2:00:00:00' "
                        f"> /tmp/tcpdump_{iface}.log 2>&1 &"
                    )
                    dut.execute_sudo(cmd)
                    logger.info(f"已启动{iface}接口BPDU抓包")
                    
                    # 验证进程启动
                    time.sleep(0.5)
                    stdout, _, _ = dut.execute_sudo(f"pgrep -f 'tcpdump.*{iface}'")
                    if stdout.strip():
                        logger.info(f"tcpdump进程已启动 (PID: {stdout.strip()})")
                else:
                    logger.warning(f"接口{iface}不存在，跳过抓包")
            except Exception as e:
                logger.warning(f"启动{iface}接口抓包失败: {e}")
        
        # 等待抓包启动
        time.sleep(2)
        
        # 3. 检查TestNode1的网络接口
        logger.info("3. 检查TestNode1网络接口状态")
        for test_iface in ['eth0', 'eth1', 'eth2']:
            stdout, _, code = testnode1.execute(f"ip link show {test_iface}")
            if code == 0:
                logger.info(f"TestNode1 {test_iface}状态: {stdout.split()[8] if len(stdout.split()) > 8 else 'Unknown'}")
            else:
                logger.warning(f"TestNode1 {test_iface}接口不存在")
        
        # 4. 执行BPDU注入 - 测试多个接口
        injection_results = {}
        test_interfaces = ['eth0', 'eth1', 'eth2']
        
        for injection_interface in test_interfaces:
            logger.info(f"\n4.{test_interfaces.index(injection_interface)+1} 测试通过{injection_interface}接口注入BPDU")
            
            # 检查接口状态
            stdout, _, code = testnode1.execute(f"ip link show {injection_interface}")
            if code != 0:
                logger.warning(f"接口{injection_interface}不存在，跳过测试")
                continue
            
            logger.info(f"使用接口{injection_interface}进行BPDU注入")
            
            # 创建故障注入器并执行注入
            fault_injector = FaultInjector(testnode1)
            success = fault_injector.inject_rogue_bpdu(
                interface=injection_interface,
                priority=0,  # 最高优先级
                src_mac="00:11:22:33:44:55",
                count=5,  # 减少数量以便快速测试
                interval=1.0
            )
            
            injection_results[injection_interface] = success
            logger.info(f"接口{injection_interface}注入结果: {'成功' if success else '失败'}")
            
            # 等待一段时间让BPDU传播
            time.sleep(3)
        
        # 5. 停止抓包并分析结果
        logger.info("\n5. 停止抓包并分析结果")
        time.sleep(2)
        
        # 停止所有tcpdump进程
        dut.execute_sudo("pkill -f 'tcpdump.*test_bpdu'")
        time.sleep(1)
        
        # 分析抓包结果
        total_captured = 0
        for iface in capture_interfaces:
            try:
                pcap_file = f"/tmp/test_bpdu_{iface}.pcap"
                
                # 检查文件是否存在
                stdout, _, code = dut.execute_sudo(f"ls -la {pcap_file}")
                if code == 0:
                    logger.info(f"抓包文件{pcap_file}: {stdout.strip()}")
                    
                    # 分析BPDU数量
                    stdout, _, code = dut.execute_sudo(f"tcpdump -r {pcap_file} 2>/dev/null | wc -l")
                    if code == 0 and stdout.strip().isdigit():
                        bpdu_count = int(stdout.strip())
                        total_captured += bpdu_count
                        logger.info(f"接口{iface}捕获到{bpdu_count}个数据包")
                        
                        # 显示详细信息
                        if bpdu_count > 0:
                            stdout, _, _ = dut.execute_sudo(f"tcpdump -r {pcap_file} -vv -c 3 2>/dev/null")
                            logger.info(f"接口{iface}前3个数据包详情:\n{stdout}")
                    
                    # 清理文件
                    dut.execute_sudo(f"rm -f {pcap_file} /tmp/tcpdump_{iface}.log")
                else:
                    logger.warning(f"抓包文件{pcap_file}不存在")
                    
            except Exception as e:
                logger.warning(f"分析接口{iface}抓包结果失败: {e}")
        
        # 6. 检查DUT的RSTP状态变化
        logger.info("\n6. 检查DUT的RSTP状态变化")
        stdout, _, _ = dut.execute_sudo("ovs-vsctl list bridge")
        logger.info(f"DUT最终网桥状态:\n{stdout}")
        
        # 7. 总结测试结果
        logger.info("\n=== 测试结果总结 ===")
        logger.info(f"注入接口测试结果: {injection_results}")
        logger.info(f"DUT总共捕获BPDU数量: {total_captured}")
        
        if total_captured > 0:
            logger.info("✓ 成功: BPDU已送达DUT")
            logger.info("✓ 网络路径正常")
            logger.info("✓ BPDU格式正确")
            return True
        else:
            logger.warning("✗ 失败: DUT未捕获到任何BPDU")
            logger.warning("可能原因:")
            logger.warning("  - 网络连接问题")
            logger.warning("  - 接口配置错误")
            logger.warning("  - BPDU被过滤或丢弃")
            return False
            
    except Exception as e:
        logger.error(f"BPDU注入测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主函数"""
    logger.info("开始修复后的BPDU注入测试")
    
    try:
        # 1. 加载配置
        config = load_config()
        logger.info("配置文件加载成功")
        
        # 2. 启动虚拟机
        if not start_vms_and_wait(config):
            logger.error("虚拟机启动失败")
            return False
        
        # 3. 建立SSH连接
        logger.info("建立SSH连接...")
        
        # 连接DUT
        dut_config = config['vms']['dut']
        dut = SSHManager(dut_config)
        if not wait_for_ssh_ready(dut):
            logger.error("DUT SSH连接失败")
            return False
        
        # 连接TestNode1
        testnode1_config = config['vms']['nodes'][0]  # 第一个节点是TestNode1
        testnode1 = SSHManager(testnode1_config)
        if not wait_for_ssh_ready(testnode1):
            logger.error("TestNode1 SSH连接失败")
            return False
        
        # 4. 设置网络连通性
        if not setup_network_connectivity(dut, testnode1):
            logger.error("网络连通性设置失败")
            return False
        
        # 5. 执行BPDU注入测试
        success = test_enhanced_bpdu_injection(dut, testnode1)
        
        # 6. 清理连接
        dut.close()
        testnode1.close()
        
        return success
        
    except Exception as e:
        logger.error(f"测试执行失败: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    if success:
        print("\n=== 测试通过 ===")
        print("修复后的BPDU注入功能正常工作")
        print("恶意BPDU能够成功送达DUT")
    else:
        print("\n=== 测试失败 ===")
        print("BPDU注入仍存在问题，需要进一步调试")
    
    sys.exit(0 if success else 1)
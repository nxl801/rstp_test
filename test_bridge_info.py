#!/usr/bin/env python3

import sys
sys.path.append('src')

from rstp_analyzer import RSTPAnalyzer
from ssh_manager import SSHManager
from dataclasses import dataclass

@dataclass
class NodeConfig:
    name: str
    ip: str
    username: str
    password: str

class MockSSHManager:
    def __init__(self):
        self.config = NodeConfig(
            name='DUT',
            ip='192.168.1.100',
            username='admin',
            password='admin'
        )
    
    def execute_as_root(self, command):
        """模拟SSH执行命令"""
        print(f"执行命令: {command}")
        
        if "ovs-ofctl show SE_ETH2" in command:
            # 模拟返回包含eth1的端口列表
            return """OFPT_FEATURES_REPLY (xid=0x2): dpid:0000525400123456
n_tables:254, n_buffers:0
capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS ARP_MATCH_IP
actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan mod_dl_src mod_dl_dst mod_nw_src mod_nw_dst mod_nw_tos mod_tp_src mod_tp_dst
 1(eth0): addr:52:54:00:12:34:56
     config:     0
     state:      0
     current:    10GB-FD COPPER AUTO_NEG
 2(eth1): addr:52:54:00:12:34:57
     config:     0
     state:      0
     current:    10GB-FD COPPER AUTO_NEG
 3(eth2): addr:52:54:00:12:34:58
     config:     0
     state:      0
     current:    10GB-FD COPPER AUTO_NEG
 4(eth3): addr:52:54:00:12:34:59
     config:     0
     state:      0
     current:    10GB-FD COPPER AUTO_NEG
""", "", 0
        elif "ovs-appctl rstp/show SE_ETH2" in command:
            # 模拟RSTP输出
            return """---- SE_ETH2 ----
Root ID:
  priority    32768
  address     52:54:00:12:34:56
  This bridge is the root
  hello time   2.00 s  max age 20.00 s  forward delay 15.00 s

Bridge ID:
  priority    32768
  address     52:54:00:12:34:56
  hello time   2.00 s  max age 20.00 s  forward delay 15.00 s

Interface           Role Sts Cost      Prio.Nbr Type
---------------- ---- --- --------- -------- --------------------------------
""", "", 0
        else:
            # 模拟SSH连接超时
            return "", "ssh: connect to host 192.168.1.100 port 22: Connection timed out", 1
    
    def execute(self, cmd):
        return self.execute_as_root(cmd)

def main():
    print("测试修正后的get_bridge_info方法...")
    
    # 创建模拟DUT节点
    dut = MockSSHManager()
    analyzer = RSTPAnalyzer(dut)
    
    # 获取SE_ETH2网桥信息
    info = analyzer.get_bridge_info('SE_ETH2')
    
    print("\n=== Bridge Info ===")
    print(f"Bridge ID: {info.bridge_id}")
    print(f"Root ID: {info.root_id}")
    print(f"Root Port: {info.root_port}")
    print(f"Ports: {list(info.ports.keys())}")
    
    print("\n=== Port Details ===")
    for name, port in info.ports.items():
        print(f"  {name}: role={port.role.name}, state={port.state.name}")
    
    # 检查是否成功获取到eth1端口
    if 'eth1' in info.ports:
        print("\n✅ 成功！现在能正确获取到eth1端口")
    else:
        print("\n❌ 仍然没有获取到eth1端口")
        print("实际获取到的端口:", list(info.ports.keys()))

if __name__ == "__main__":
    main()
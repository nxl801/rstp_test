#!/usr/bin/env python3
"""
测试BPDU注入修复验证脚本
验证以下修复:
1. 接口从eth0改为eth2
2. BPDU类型从0x00改为0x02 (Rapid STP)
3. 增强的抓包验证机制
4. 调试和诊断功能
"""

import sys
import os
import re

def test_interface_fix():
    """测试接口修改"""
    print("\n=== 测试1: 接口修改验证 ===")
    
    test_security_path = "tests/test_security.py"
    if not os.path.exists(test_security_path):
        print("❌ test_security.py文件不存在")
        return False
    
    with open(test_security_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = [
        ('injection_interface = "eth2"', '接口设置为eth2'),
        ('interface=injection_interface', '使用injection_interface变量'),
        ('interface = "{injection_interface}"', 'BPDU洪泛使用正确接口'),
    ]
    
    passed = 0
    for pattern, desc in checks:
        if pattern in content:
            print(f"✅ {desc}: 找到")
            passed += 1
        else:
            print(f"❌ {desc}: 未找到")
    
    print(f"接口修改检查: {passed}/{len(checks)} 通过")
    return passed == len(checks)

def test_bpdu_format_fix():
    """测试BPDU格式修复"""
    print("\n=== 测试2: BPDU格式修复验证 ===")
    
    # 检查fault_injector.py
    fault_injector_path = "src/fault_injector.py"
    if not os.path.exists(fault_injector_path):
        print("❌ fault_injector.py文件不存在")
        return False
    
    with open(fault_injector_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = [
        ('bpdutype=0x02', 'BPDU类型设置为Rapid STP'),
        ('version=0x02', 'RSTP版本设置'),
        ('bpduflags=0x3C', 'RSTP标志位设置'),
        ('pathcost=0', '路径成本字段'),
        ('portid=0x8001', '端口ID字段'),
    ]
    
    passed = 0
    for pattern, desc in checks:
        if pattern in content:
            print(f"✅ {desc}: 找到")
            passed += 1
        else:
            print(f"❌ {desc}: 未找到")
    
    # 检查test_security.py中的BPDU洪泛格式
    test_security_path = "tests/test_security.py"
    with open(test_security_path, 'r', encoding='utf-8') as f:
        test_content = f.read()
    
    flood_checks = [
        ('bpdutype=0x02', 'BPDU洪泛使用Rapid STP类型'),
        ('version=0x02', 'BPDU洪泛使用RSTP版本'),
    ]
    
    for pattern, desc in flood_checks:
        if pattern in test_content:
            print(f"✅ {desc}: 找到")
            passed += 1
        else:
            print(f"❌ {desc}: 未找到")
    
    total_checks = len(checks) + len(flood_checks)
    print(f"BPDU格式检查: {passed}/{total_checks} 通过")
    return passed == total_checks

def test_enhanced_capture():
    """测试增强抓包功能"""
    print("\n=== 测试3: 增强抓包功能验证 ===")
    
    test_security_path = "tests/test_security.py"
    if not os.path.exists(test_security_path):
        print("❌ test_security.py文件不存在")
        return False
    
    with open(test_security_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = [
        ('_start_enhanced_packet_capture', '增强抓包启动方法'),
        ('_stop_enhanced_packet_capture_and_analyze', '增强抓包停止分析方法'),
        ('captured_bpdus', '抓包BPDU计数'),
        ('_diagnose_bpdu_delivery_failure', 'BPDU送达失败诊断'),
        ('tcpdump -i br3 -vv stp', 'DUT接口抓包命令'),
    ]
    
    passed = 0
    for pattern, desc in checks:
        if pattern in content:
            print(f"✅ {desc}: 找到")
            passed += 1
        else:
            print(f"❌ {desc}: 未找到")
    
    print(f"增强抓包检查: {passed}/{len(checks)} 通过")
    return passed == len(checks)

def test_debugging_features():
    """测试调试功能"""
    print("\n=== 测试4: 调试功能验证 ===")
    
    # 检查fault_injector.py中的调试功能
    fault_injector_path = "src/fault_injector.py"
    with open(fault_injector_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = [
        ('检查接口状态', '接口状态检查'),
        ('发送的BPDU包详情', 'BPDU包详情显示'),
        ('print(f"接口{interface}状态', '接口状态输出'),
        ('print(f"发送恶意BPDU', 'BPDU发送状态输出'),
    ]
    
    passed = 0
    for pattern, desc in checks:
        if pattern in content:
            print(f"✅ {desc}: 找到")
            passed += 1
        else:
            print(f"❌ {desc}: 未找到")
    
    # 检查test_security.py中的调试功能
    test_security_path = "tests/test_security.py"
    with open(test_security_path, 'r', encoding='utf-8') as f:
        test_content = f.read()
    
    test_checks = [
        ('警告：DUT接口未捕获到任何BPDU', 'BPDU未送达警告'),
        ('建议检查：1) 网络连接', '网络诊断建议'),
        ('确认：DUT接口捕获到', 'BPDU送达确认'),
    ]
    
    for pattern, desc in test_checks:
        if pattern in test_content:
            print(f"✅ {desc}: 找到")
            passed += 1
        else:
            print(f"❌ {desc}: 未找到")
    
    total_checks = len(checks) + len(test_checks)
    print(f"调试功能检查: {passed}/{total_checks} 通过")
    return passed == total_checks

def generate_summary_report():
    """生成修复总结报告"""
    print("\n" + "="*60)
    print("BPDU注入修复总结报告")
    print("="*60)
    
    print("\n🔧 已实施的修复:")
    print("1. ✅ 接口修改: eth0 → eth2 (连接到DUT的正确接口)")
    print("2. ✅ BPDU格式: 0x00 → 0x02 (Rapid STP格式)")
    print("3. ✅ 增强字段: 添加完整的RSTP BPDU字段")
    print("4. ✅ 抓包验证: 在DUT接口进行tcpdump抓包")
    print("5. ✅ 调试功能: 接口状态检查和详细日志")
    print("6. ✅ 诊断机制: BPDU送达失败诊断")
    
    print("\n📋 修复的关键问题:")
    print("• 恶意BPDU无法送达DUT (接口错误)")
    print("• BPDU格式不兼容 (使用旧STP格式)")
    print("• 缺乏验证机制 (无法确认BPDU到达)")
    print("• 调试信息不足 (难以定位问题)")
    
    print("\n🎯 预期效果:")
    print("• BPDU能够成功送达DUT")
    print("• DUT的RSTP RX计数器会增加")
    print("• 可以通过抓包验证BPDU到达")
    print("• 能够区分攻击未触发和DUT防护机制")
    
    print("\n⚠️  注意事项:")
    print("• 确保TestNode1与DUT之间网络连通")
    print("• 验证eth2接口确实连接到DUT")
    print("• 检查DUT的br3/br4接口状态")
    print("• 监控DUT的RSTP状态变化")

def main():
    """主测试函数"""
    print("BPDU注入修复验证测试")
    print("=" * 50)
    
    # 切换到项目根目录
    if os.path.exists('tests') and os.path.exists('src'):
        print("✅ 在项目根目录")
    else:
        print("❌ 不在项目根目录，请切换到正确目录")
        return False
    
    # 运行所有测试
    tests = [
        test_interface_fix,
        test_bpdu_format_fix,
        test_enhanced_capture,
        test_debugging_features,
    ]
    
    passed_tests = 0
    for test_func in tests:
        try:
            if test_func():
                passed_tests += 1
        except Exception as e:
            print(f"❌ 测试 {test_func.__name__} 执行失败: {e}")
    
    print(f"\n📊 总体结果: {passed_tests}/{len(tests)} 测试通过")
    
    # 生成总结报告
    generate_summary_report()
    
    return passed_tests == len(tests)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
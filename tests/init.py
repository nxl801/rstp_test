"""
RSTP测试套件包
"""

# 测试标记
MARKS = {
    'protocol_conformance': '协议一致性测试',
    'convergence': '收敛测试',
    'parameters': '参数配置测试',
    'security': '安全性测试',
    'high_availability': '高可用性测试',
    'slow': '慢速测试',
    'critical': '关键测试'
}

# 测试优先级
PRIORITIES = {
    'CRITICAL': 1,
    'HIGH': 2,
    'MEDIUM': 3,
    'LOW': 4
}

__all__ = ['MARKS', 'PRIORITIES']
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试用例稳定性分析工具
分析test_root_bridge_hijack_attack测试用例的稳定性问题
"""

import time
import logging
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TestStabilityAnalyzer:
    """测试稳定性分析器"""
    
    def __init__(self):
        self.test_results = []
        self.execution_times = []
        self.bpdu_counts = []
        
    def run_test_multiple_times(self, num_runs: int = 5) -> Dict[str, Any]:
        """多次运行测试并收集数据"""
        logger.info(f"开始运行测试 {num_runs} 次以分析稳定性")
        
        for i in range(num_runs):
            logger.info(f"\n=== 第 {i+1}/{num_runs} 次测试 ===")
            start_time = time.time()
            
            try:
                # 运行测试
                result = subprocess.run([
                    'python', '-m', 'pytest', 
                    'tests/test_security.py::TestSecurity::test_root_bridge_hijack_attack',
                    '-v', '-s', '--tb=short'
                ], capture_output=True, text=True, timeout=600)
                
                end_time = time.time()
                execution_time = end_time - start_time
                
                # 分析结果
                test_passed = result.returncode == 0
                output = result.stdout + result.stderr
                
                # 提取关键信息
                bpdu_info = self._extract_bpdu_info(output)
                timing_info = self._extract_timing_info(output)
                
                test_data = {
                    'run_number': i + 1,
                    'passed': test_passed,
                    'execution_time': execution_time,
                    'bpdu_info': bpdu_info,
                    'timing_info': timing_info,
                    'output': output
                }
                
                self.test_results.append(test_data)
                self.execution_times.append(execution_time)
                
                logger.info(f"测试 {i+1} 结果: {'通过' if test_passed else '失败'}, 耗时: {execution_time:.1f}秒")
                
                # 等待一段时间再运行下一次测试
                if i < num_runs - 1:
                    logger.info("等待5秒后运行下一次测试...")
                    time.sleep(5)
                    
            except subprocess.TimeoutExpired:
                logger.error(f"测试 {i+1} 超时")
                self.test_results.append({
                    'run_number': i + 1,
                    'passed': False,
                    'execution_time': 600,
                    'error': 'timeout'
                })
            except Exception as e:
                logger.error(f"测试 {i+1} 异常: {e}")
                self.test_results.append({
                    'run_number': i + 1,
                    'passed': False,
                    'error': str(e)
                })
        
        return self._analyze_results()
    
    def _extract_bpdu_info(self, output: str) -> Dict[str, Any]:
        """从输出中提取BPDU相关信息"""
        bpdu_info = {
            'initial_rx': 0,
            'final_rx': 0,
            'increment': 0,
            'injection_success': False
        }
        
        # 提取BPDU接收计数
        initial_match = re.search(r'初始BPDU接收计数: (\d+)', output)
        if initial_match:
            bpdu_info['initial_rx'] = int(initial_match.group(1))
            
        final_match = re.search(r'最终BPDU接收计数: (\d+)', output)
        if final_match:
            bpdu_info['final_rx'] = int(final_match.group(1))
            
        increment_match = re.search(r'BPDU接收增量: (\d+)', output)
        if increment_match:
            bpdu_info['increment'] = int(increment_match.group(1))
            
        # 检查注入是否成功
        bpdu_info['injection_success'] = 'BPDU注入成功' in output or '成功发送' in output
        
        return bpdu_info
    
    def _extract_timing_info(self, output: str) -> Dict[str, Any]:
        """从输出中提取时序信息"""
        timing_info = {
            'convergence_time': 0,
            'attack_duration': 0,
            'total_test_time': 0
        }
        
        # 提取测试总时间
        time_match = re.search(r'耗时: ([\d.]+)秒', output)
        if time_match:
            timing_info['total_test_time'] = float(time_match.group(1))
            
        return timing_info
    
    def _analyze_results(self) -> Dict[str, Any]:
        """分析测试结果"""
        if not self.test_results:
            return {'error': '没有测试结果'}
            
        passed_count = sum(1 for r in self.test_results if r.get('passed', False))
        total_count = len(self.test_results)
        success_rate = passed_count / total_count * 100
        
        # 执行时间分析
        valid_times = [t for t in self.execution_times if t < 600]  # 排除超时
        if valid_times:
            avg_time = sum(valid_times) / len(valid_times)
            min_time = min(valid_times)
            max_time = max(valid_times)
            time_variance = max_time - min_time
        else:
            avg_time = min_time = max_time = time_variance = 0
            
        # BPDU分析
        bpdu_success_count = sum(1 for r in self.test_results 
                               if r.get('bpdu_info', {}).get('injection_success', False))
        bpdu_success_rate = bpdu_success_count / total_count * 100
        
        analysis = {
            'summary': {
                'total_runs': total_count,
                'passed_runs': passed_count,
                'success_rate': success_rate,
                'stability_rating': self._calculate_stability_rating(success_rate, time_variance)
            },
            'timing_analysis': {
                'average_time': avg_time,
                'min_time': min_time,
                'max_time': max_time,
                'time_variance': time_variance,
                'variance_percentage': (time_variance / avg_time * 100) if avg_time > 0 else 0
            },
            'bpdu_analysis': {
                'injection_success_rate': bpdu_success_rate,
                'bpdu_delivery_issues': bpdu_success_rate < 100
            },
            'detailed_results': self.test_results
        }
        
        return analysis
    
    def _calculate_stability_rating(self, success_rate: float, time_variance: float) -> str:
        """计算稳定性评级"""
        if success_rate == 100 and time_variance < 60:
            return "优秀"
        elif success_rate >= 80 and time_variance < 120:
            return "良好"
        elif success_rate >= 60:
            return "一般"
        else:
            return "差"
    
    def generate_report(self, analysis: Dict[str, Any]) -> str:
        """生成分析报告"""
        report = []
        report.append("=" * 60)
        report.append("测试稳定性分析报告")
        report.append("=" * 60)
        report.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # 总体概况
        summary = analysis['summary']
        report.append("📊 总体概况:")
        report.append(f"  总运行次数: {summary['total_runs']}")
        report.append(f"  成功次数: {summary['passed_runs']}")
        report.append(f"  成功率: {summary['success_rate']:.1f}%")
        report.append(f"  稳定性评级: {summary['stability_rating']}")
        report.append("")
        
        # 时序分析
        timing = analysis['timing_analysis']
        report.append("⏱️ 执行时间分析:")
        report.append(f"  平均执行时间: {timing['average_time']:.1f}秒")
        report.append(f"  最短执行时间: {timing['min_time']:.1f}秒")
        report.append(f"  最长执行时间: {timing['max_time']:.1f}秒")
        report.append(f"  时间差异: {timing['time_variance']:.1f}秒")
        report.append(f"  差异百分比: {timing['variance_percentage']:.1f}%")
        report.append("")
        
        # BPDU分析
        bpdu = analysis['bpdu_analysis']
        report.append("📡 BPDU注入分析:")
        report.append(f"  BPDU注入成功率: {bpdu['injection_success_rate']:.1f}%")
        report.append(f"  存在BPDU传输问题: {'是' if bpdu['bpdu_delivery_issues'] else '否'}")
        report.append("")
        
        # 稳定性问题分析
        report.append("🔍 稳定性问题分析:")
        issues = self._identify_stability_issues(analysis)
        if issues:
            for issue in issues:
                report.append(f"  ⚠️ {issue}")
        else:
            report.append("  ✅ 未发现明显的稳定性问题")
        report.append("")
        
        # 改进建议
        report.append("💡 改进建议:")
        recommendations = self._generate_recommendations(analysis)
        for rec in recommendations:
            report.append(f"  • {rec}")
        report.append("")
        
        # 详细结果
        report.append("📋 详细测试结果:")
        for result in analysis['detailed_results']:
            status = "✅" if result.get('passed', False) else "❌"
            time_str = f"{result.get('execution_time', 0):.1f}s"
            report.append(f"  {status} 测试 {result['run_number']}: {time_str}")
            
            if 'bpdu_info' in result:
                bpdu_info = result['bpdu_info']
                report.append(f"      BPDU增量: {bpdu_info.get('increment', 0)}")
                report.append(f"      注入成功: {'是' if bpdu_info.get('injection_success', False) else '否'}")
        
        return "\n".join(report)
    
    def _identify_stability_issues(self, analysis: Dict[str, Any]) -> List[str]:
        """识别稳定性问题"""
        issues = []
        
        summary = analysis['summary']
        timing = analysis['timing_analysis']
        bpdu = analysis['bpdu_analysis']
        
        if summary['success_rate'] < 100:
            issues.append(f"测试成功率不稳定 ({summary['success_rate']:.1f}%)")
            
        if timing['variance_percentage'] > 50:
            issues.append(f"执行时间差异过大 ({timing['variance_percentage']:.1f}%)")
            
        if bpdu['bpdu_delivery_issues']:
            issues.append(f"BPDU传输不稳定 (成功率: {bpdu['injection_success_rate']:.1f}%)")
            
        # 检查是否有超时
        timeout_count = sum(1 for r in analysis['detailed_results'] 
                          if r.get('error') == 'timeout')
        if timeout_count > 0:
            issues.append(f"存在测试超时 ({timeout_count}次)")
            
        return issues
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """生成改进建议"""
        recommendations = []
        
        timing = analysis['timing_analysis']
        bpdu = analysis['bpdu_analysis']
        
        # 时序相关建议
        if timing['variance_percentage'] > 30:
            recommendations.extend([
                "增加网络收敛等待时间 (当前10秒可能不够)",
                "在关键步骤之间添加更多的状态验证",
                "实现自适应等待机制，根据网络状态动态调整等待时间"
            ])
            
        # BPDU相关建议
        if bpdu['bpdu_delivery_issues']:
            recommendations.extend([
                "增加BPDU发送重试机制",
                "验证网络接口状态后再发送BPDU",
                "添加BPDU发送确认机制"
            ])
            
        # 通用建议
        recommendations.extend([
            "添加测试前的环境清理步骤",
            "实现测试状态的完整重置",
            "增加更详细的日志记录以便调试",
            "考虑添加测试重试机制"
        ])
        
        return recommendations

def main():
    """主函数"""
    analyzer = TestStabilityAnalyzer()
    
    logger.info("开始测试稳定性分析...")
    analysis = analyzer.run_test_multiple_times(num_runs=3)
    
    report = analyzer.generate_report(analysis)
    
    # 输出报告
    print("\n" + report)
    
    # 保存报告到文件
    report_file = f"test_stability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    logger.info(f"分析报告已保存到: {report_file}")

if __name__ == "__main__":
    main()
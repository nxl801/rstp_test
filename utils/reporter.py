"""
测试报告生成模块
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import pandas as pd
from jinja2 import Template


@dataclass
class TestResult:
    """测试结果"""
    test_name: str
    test_category: str
    status: str  # PASS/FAIL/SKIP
    duration: float
    timestamp: str
    error_message: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None


@dataclass
class TestSummary:
    """测试摘要"""
    total_tests: int
    passed: int
    failed: int
    skipped: int
    pass_rate: float
    total_duration: float
    start_time: str
    end_time: str


class TestReporter:
    """测试报告生成器"""

    def __init__(self, report_dir: str = "./reports"):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, results: List[Dict[str, Any]],
                        output_file: Optional[str] = None) -> Path:
        """
        生成测试报告

        Args:
            results: 测试结果列表
            output_file: 输出文件名

        Returns:
            报告文件路径
        """
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"rstp_test_report_{timestamp}.html"

        output_path = self.report_dir / output_file

        # 生成摘要
        summary = self._generate_summary(results)

        # 生成HTML报告
        html_content = self._generate_html(results, summary)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        # 同时生成JSON报告
        json_path = output_path.with_suffix('.json')
        self._generate_json_report(results, summary, json_path)

        # 生成CSV报告
        csv_path = output_path.with_suffix('.csv')
        self._generate_csv_report(results, csv_path)

        return output_path

    def _generate_summary(self, results: List[Dict[str, Any]]) -> TestSummary:
        """生成测试摘要"""
        total = len(results)
        passed = sum(1 for r in results if r.get('status') == 'PASS')
        failed = sum(1 for r in results if r.get('status') == 'FAIL')
        skipped = sum(1 for r in results if r.get('status') == 'SKIP')

        total_duration = sum(r.get('duration', 0) for r in results)

        timestamps = [r.get('timestamp', '') for r in results if r.get('timestamp')]
        start_time = min(timestamps) if timestamps else ''
        end_time = max(timestamps) if timestamps else ''

        pass_rate = (passed / total * 100) if total > 0 else 0

        return TestSummary(
            total_tests=total,
            passed=passed,
            failed=failed,
            skipped=skipped,
            pass_rate=pass_rate,
            total_duration=total_duration,
            start_time=start_time,
            end_time=end_time
        )

    def _generate_html(self, results: List[Dict[str, Any]],
                       summary: TestSummary) -> str:
        """生成HTML报告"""
        template = Template("""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RSTP自动化测试报告</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }

        /* 头部 */
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; }

        /* 摘要卡片 */
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .card-title {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        .card-value {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        .card.pass { border-left: 4px solid #4caf50; }
        .card.fail { border-left: 4px solid #f44336; }
        .card.skip { border-left: 4px solid #ff9800; }

        /* 图表容器 */
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        /* 测试结果表格 */
        .results-table {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #666;
            border-bottom: 2px solid #dee2e6;
        }
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #dee2e6;
        }
        tr:hover { background: #f8f9fa; }

        /* 状态标签 */
        .status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .status.pass {
            background: #d4edda;
            color: #155724;
        }
        .status.fail {
            background: #f8d7da;
            color: #721c24;
        }
        .status.skip {
            background: #fff3cd;
            color: #856404;
        }

        /* 进度条 */
        .progress-bar {
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
        }
        .progress-segment {
            float: left;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
        .progress-pass { background: #4caf50; }
        .progress-fail { background: #f44336; }
        .progress-skip { background: #ff9800; }

        /* 页脚 */
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 40px;
        }

        /* 响应式 */
        @media (max-width: 768px) {
            .summary-cards { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔬 RSTP自动化测试报告</h1>
            <p>生成时间: {{ current_time }}</p>
        </div>

        <div class="summary-cards">
            <div class="card">
                <div class="card-title">总测试数</div>
                <div class="card-value">{{ summary.total_tests }}</div>
            </div>
            <div class="card pass">
                <div class="card-title">通过</div>
                <div class="card-value">{{ summary.passed }}</div>
            </div>
            <div class="card fail">
                <div class="card-title">失败</div>
                <div class="card-value">{{ summary.failed }}</div>
            </div>
            <div class="card skip">
                <div class="card-title">跳过</div>
                <div class="card-value">{{ summary.skipped }}</div>
            </div>
            <div class="card">
                <div class="card-title">通过率</div>
                <div class="card-value">{{ "%.1f"|format(summary.pass_rate) }}%</div>
            </div>
            <div class="card">
                <div class="card-title">总耗时</div>
                <div class="card-value">{{ "%.1f"|format(summary.total_duration) }}s</div>
            </div>
        </div>

        <div class="chart-container">
            <h2>测试进度</h2>
            <div class="progress-bar">
                {% if summary.total_tests > 0 %}
                <div class="progress-segment progress-pass" style="width: {{ summary.passed / summary.total_tests * 100 }}%">
                    {{ summary.passed }}
                </div>
                <div class="progress-segment progress-fail" style="width: {{ summary.failed / summary.total_tests * 100 }}%">
                    {% if summary.failed > 0 %}{{ summary.failed }}{% endif %}
                </div>
                <div class="progress-segment progress-skip" style="width: {{ summary.skipped / summary.total_tests * 100 }}%">
                    {% if summary.skipped > 0 %}{{ summary.skipped }}{% endif %}
                </div>
                {% endif %}
            </div>
        </div>

        <div class="results-table">
            <table>
                <thead>
                    <tr>
                        <th>测试名称</th>
                        <th>类别</th>
                        <th>状态</th>
                        <th>耗时(秒)</th>
                        <th>错误信息</th>
                    </tr>
                </thead>
                <tbody>
                    {% for result in results %}
                    <tr>
                        <td><strong>{{ result.test_name }}</strong></td>
                        <td>{{ result.get('category', '-') }}</td>
                        <td>
                            <span class="status {{ result.status|lower }}">
                                {{ result.status }}
                            </span>
                        </td>
                        <td>{{ "%.2f"|format(result.get('duration', 0)) }}</td>
                        <td>{{ result.get('error_message', '-') }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>© 2024 RSTP Testing Framework | 施耐德电气</p>
        </div>
    </div>
</body>
</html>
        """)

        return template.render(
            summary=summary,
            results=results,
            current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )

    def _generate_json_report(self, results: List[Dict[str, Any]],
                              summary: TestSummary, output_path: Path):
        """生成JSON报告"""
        report = {
            'summary': asdict(summary),
            'results': results,
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'framework_version': '1.0.0'
            }
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    def _generate_csv_report(self, results: List[Dict[str, Any]],
                             output_path: Path):
        """生成CSV报告"""
        df = pd.DataFrame(results)
        df.to_csv(output_path, index=False, encoding='utf-8')
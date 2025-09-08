#!/usr/bin/env python3
"""
RSTP自动化测试主执行脚本
"""

import os
import sys
import argparse
import logging
from pathlib import Path
from datetime import datetime

import pytest


def setup_environment():
    """设置测试环境"""
    # 创建必要的目录
    dirs = ['logs', 'reports', 'temp']
    for dir_name in dirs:
        Path(dir_name).mkdir(exist_ok=True)


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='RSTP自动化测试框架',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s                     # 运行所有测试
  %(prog)s -m protocol         # 只运行协议一致性测试
  %(prog)s -m convergence      # 只运行收敛测试
  %(prog)s --verbose           # 详细输出
  %(prog)s --parallel 4        # 并行运行(4个进程)
        """
    )

    parser.add_argument(
        '-m', '--mark',
        choices=['protocol_conformance', 'convergence', 'parameters',
                 'security', 'high_availability'],
        help='运行特定类别的测试'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='详细输出'
    )

    parser.add_argument(
        '--parallel',
        type=int,
        metavar='N',
        help='并行运行测试(N个进程)'
    )

    parser.add_argument(
        '--report-only',
        action='store_true',
        help='只生成报告(使用现有结果)'
    )

    parser.add_argument(
        '--config',
        default='config.yaml',
        help='配置文件路径'
    )

    return parser.parse_args()


def run_tests(args):
    """运行测试"""
    pytest_args = []

    # 基本参数
    if args.verbose:
        pytest_args.extend(['-v', '-s'])
    else:
        pytest_args.append('-q')

    # 添加标记
    if args.mark:
        pytest_args.extend(['-m', args.mark])

    # 并行执行
    if args.parallel:
        pytest_args.extend(['-n', str(args.parallel)])

    # 报告
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    pytest_args.extend([
        '--html', f'reports/report_{timestamp}.html',
        '--self-contained-html',
        '--junit-xml', f'reports/junit_{timestamp}.xml',
    ])

    # 运行测试
    pytest_args.append('tests/')

    print(f"运行pytest: {' '.join(pytest_args)}")
    return pytest.main(pytest_args)


def main():
    """主函数"""
    args = parse_arguments()

    # 设置环境
    setup_environment()

    # 设置日志
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f'logs/test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
            logging.StreamHandler()
        ]
    )

    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("RSTP自动化测试开始")
    logger.info("=" * 60)

    if args.report_only:
        logger.info("仅生成报告模式")
        # TODO: 实现报告生成逻辑
        return 0

    # 运行测试
    result = run_tests(args)

    logger.info("=" * 60)
    logger.info(f"测试完成，返回码: {result}")
    logger.info("=" * 60)

    return result


if __name__ == '__main__':
    sys.exit(main())
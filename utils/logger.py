"""
日志配置模块
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

# 日志格式
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
DETAILED_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'

# 日志级别映射
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}


def setup_logging(log_level: str = 'INFO',
                  log_dir: str = './logs',
                  log_file: Optional[str] = None,
                  console: bool = True,
                  detailed: bool = False) -> None:
    """
    设置日志配置

    Args:
        log_level: 日志级别
        log_dir: 日志目录
        log_file: 日志文件名
        console: 是否输出到控制台
        detailed: 是否使用详细格式
    """
    # 创建日志目录
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # 确定日志文件名
    if not log_file:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = f'rstp_test_{timestamp}.log'

    log_file_path = log_path / log_file

    # 获取根logger
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVELS.get(log_level.upper(), logging.INFO))

    # 清除现有处理器
    root_logger.handlers.clear()

    # 选择格式
    formatter = logging.Formatter(
        DETAILED_FORMAT if detailed else LOG_FORMAT
    )

    # 文件处理器
    file_handler = logging.handlers.RotatingFileHandler(
        log_file_path,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # 控制台处理器
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)

        # 控制台可以有不同的级别
        console_handler.setLevel(logging.INFO)
        root_logger.addHandler(console_handler)

    # 设置第三方库日志级别
    logging.getLogger('paramiko').setLevel(logging.WARNING)
    logging.getLogger('scapy').setLevel(logging.WARNING)

    root_logger.info(f"日志系统初始化完成，日志文件: {log_file_path}")


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    获取logger实例

    Args:
        name: logger名称
        level: 日志级别

    Returns:
        Logger实例
    """
    logger = logging.getLogger(name)

    if level:
        logger.setLevel(LOG_LEVELS.get(level.upper(), logging.INFO))

    return logger


class ColoredFormatter(logging.Formatter):
    """彩色日志格式化器"""

    # ANSI颜色代码
    COLORS = {
        'DEBUG': '\033[36m',  # 青色
        'INFO': '\033[32m',  # 绿色
        'WARNING': '\033[33m',  # 黄色
        'ERROR': '\033[31m',  # 红色
        'CRITICAL': '\033[35m',  # 紫色
    }
    RESET = '\033[0m'

    def format(self, record):
        # 添加颜色
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"

        # 调用父类格式化
        result = super().format(record)

        # 恢复原始级别名
        record.levelname = levelname

        return result


def setup_colored_logging():
    """设置彩色日志输出"""
    root_logger = logging.getLogger()

    # 查找控制台处理器
    for handler in root_logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.setFormatter(ColoredFormatter(LOG_FORMAT))
            break
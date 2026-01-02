import logging
import sys
from logging import Logger

from pythonjsonlogger.json import JsonFormatter


def get_logger(name: str) -> Logger:
    """ログ出力設定済みのloggerを返す"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # 親ロガーは全てのログを通す

    formatter = JsonFormatter(["message", "asctime"], json_indent=4)

    # stdout
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.addFilter(lambda record: record.levelno < logging.ERROR)
    stdout_handler.setFormatter(formatter)

    # stderr
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.ERROR)  # ERROR以上のみ出力
    stderr_handler.setFormatter(formatter)

    logger.addHandler(stdout_handler)
    logger.addHandler(stderr_handler)

    return logger

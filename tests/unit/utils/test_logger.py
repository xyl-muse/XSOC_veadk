"""日志系统单元测试"""
import tempfile
from pathlib import Path
from loguru import logger

from src.utils.logger import setup_logger, get_logger


def test_setup_logger(temp_dir):
    """测试日志初始化"""
    log_file = temp_dir / "test.log"

    # 初始化日志
    setup_logger(log_level="DEBUG", log_file=log_file)

    # 测试日志输出
    test_message = "测试日志信息"
    logger.info(test_message)

    # 验证日志文件存在并且包含测试内容
    assert log_file.exists()
    log_content = log_file.read_text(encoding="utf-8")
    assert test_message in log_content
    assert "INFO" in log_content


def test_get_logger():
    """测试获取logger实例"""
    test_logger = get_logger("test_logger")
    assert test_logger is not None

    # 测试带名称的logger
    test_logger = get_logger()
    assert test_logger is not None


def test_logger_extra_context():
    """测试日志上下文信息"""
    log_file = tempfile.mktemp(suffix=".log")
    setup_logger(log_level="DEBUG", log_file=Path(log_file))

    # 测试带trace_id的日志
    logger_ctx = logger.bind(trace_id="test-trace-123")
    test_message = "带上下文的测试日志"
    logger_ctx.info(test_message)

    # 验证上下文信息存在
    with open(log_file, "r", encoding="utf-8") as f:
        content = f.read()
        assert test_message in content
        assert "test-trace-123" in content

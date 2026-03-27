"""pytest全局配置文件"""
import pytest
import asyncio
from pathlib import Path
from loguru import logger

# 移除默认日志处理器，避免测试时输出过多日志
logger.remove()


@pytest.fixture(scope="session")
def event_loop():
    """异步测试事件循环"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def temp_dir(tmpdir_factory):
    """临时目录"""
    return Path(tmpdir_factory.mktemp("test_xsoc_agent"))


@pytest.fixture(autouse=True)
def mock_config(monkeypatch):
    """Mock配置，避免依赖真实环境变量"""
    monkeypatch.setenv("APP_NAME", "test-xsoc-agent")
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("DEBUG", "True")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("REDIS_HOST", "localhost")
    monkeypatch.setenv("REDIS_PORT", "6379")

"""配置管理单元测试"""
from src.core.config import config, AppConfig


def test_config_instance():
    """测试配置实例"""
    assert isinstance(config, AppConfig)
    assert config is not None


def test_config_basic_fields():
    """测试基础配置字段"""
    assert config.APP_NAME == "test-xsoc-agent"
    assert config.ENVIRONMENT == "test"
    assert config.DEBUG is True
    assert config.SECRET_KEY == "test-secret-key"
    assert config.API_PREFIX == "/api/v1"


def test_llm_config():
    """测试LLM配置"""
    assert config.OPENAI_API_KEY == "test-openai-key"
    assert config.OPENAI_BASE_URL == "https://api.openai.com/v1"
    assert config.LLM_MODEL == "gpt-4o"
    assert config.LLM_TEMPERATURE == 0.1
    assert config.LLM_MAX_TOKENS == 4096


def test_redis_config():
    """测试Redis配置"""
    assert config.REDIS_HOST == "localhost"
    assert config.REDIS_PORT == 6379
    assert config.REDIS_DB == 0


def test_config_environment_properties():
    """测试环境属性判断"""
    # 测试环境
    assert config.is_development is False
    assert config.is_production is False

    # 开发环境测试
    dev_config = AppConfig(ENVIRONMENT="development")
    assert dev_config.is_development is True
    assert dev_config.is_production is False

    # 生产环境测试
    prod_config = AppConfig(ENVIRONMENT="production")
    assert prod_config.is_development is False
    assert prod_config.is_production is True


def test_config_default_values():
    """测试默认配置值"""
    # 测试未配置的字段使用默认值
    assert config.HOST == "0.0.0.0"
    assert config.PORT == 8000
    assert config.LOG_LEVEL == "INFO"
    assert config.PROMETHEUS_ENABLED is True

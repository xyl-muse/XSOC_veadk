"""异常体系单元测试"""
from src.utils.exceptions import (
    XSOCAgentError,
    ConfigError,
    LLMServiceError,
    LLMAPIKeyError,
    LLMRequestTimeoutError,
    LLMOutputFormatError,
    AgentError,
    AgentNotFoundError,
    AgentExecutionError,
    AgentStateError,
    ToolError,
    ToolNotFoundError,
    ToolExecutionError,
    ToolPermissionError,
    EventError,
    EventNotFoundError,
    EventFormatError,
    EventStateError,
    APIError,
    APIAuthenticationError,
    APIAuthorizationError,
    APIValidationError,
)


def test_base_exception():
    """测试基础异常类"""
    err = XSOCAgentError("测试错误", code=1000, details={"key": "value"})
    assert str(err) == "1000: 测试错误"
    assert err.message == "测试错误"
    assert err.code == 1000
    assert err.details == {"key": "value"}


def test_config_error():
    """测试配置错误"""
    err = ConfigError("配置项缺失", details={"missing_key": "API_KEY"})
    assert err.code == 1000
    assert "配置错误" in str(err)
    assert "配置项缺失" in str(err)
    assert err.details == {"missing_key": "API_KEY"}


def test_llm_exceptions():
    """测试LLM相关异常"""
    err = LLMAPIKeyError()
    assert err.code == 2000
    assert "LLM API密钥未配置" in str(err)

    err = LLMRequestTimeoutError()
    assert err.code == 2000
    assert "LLM请求超时" in str(err)

    err = LLMOutputFormatError()
    assert err.code == 2000
    assert "LLM输出格式不符合要求" in str(err)

    err = LLMServiceError("自定义LLM错误")
    assert err.code == 2000
    assert "自定义LLM错误" in str(err)


def test_agent_exceptions():
    """测试智能体相关异常"""
    err = AgentNotFoundError("test-agent")
    assert err.code == 3001
    assert "智能体不存在: test-agent" in str(err)

    err = AgentExecutionError("test-agent", "执行失败")
    assert err.code == 3002
    assert "智能体[test-agent]执行失败: 执行失败" in str(err)

    err = AgentStateError("test-agent", "idle", "running")
    assert err.code == 3003
    assert "智能体[test-agent]状态错误" in str(err)
    assert "当前状态: idle, 期望状态: running" in str(err)


def test_tool_exceptions():
    """测试工具相关异常"""
    err = ToolNotFoundError("test-tool")
    assert err.code == 4001
    assert "工具不存在: test-tool" in str(err)

    err = ToolExecutionError("test-tool", "调用失败")
    assert err.code == 4002
    assert "工具[test-tool]执行失败: 调用失败" in str(err)

    err = ToolPermissionError("test-tool")
    assert err.code == 4003
    assert "工具调用权限不足: test-tool" in str(err)


def test_event_exceptions():
    """测试事件相关异常"""
    err = EventNotFoundError("event-123")
    assert err.code == 5001
    assert "事件不存在: event-123" in str(err)

    err = EventFormatError("字段缺失")
    assert err.code == 5002
    assert "事件格式错误: 字段缺失" in str(err)

    err = EventStateError("event-123", "completed", ["pending", "investigating"])
    assert err.code == 5003
    assert "事件[event-123]状态错误" in str(err)
    assert "当前状态: completed, 允许状态: ['pending', 'investigating']" in str(err)


def test_api_exceptions():
    """测试API相关异常"""
    err = APIAuthenticationError()
    assert err.code == 6001
    assert "认证失败" in str(err)

    err = APIAuthorizationError()
    assert err.code == 6002
    assert "权限不足" in str(err)

    err = APIValidationError("参数错误")
    assert err.code == 6003
    assert "参数验证失败: 参数错误" in str(err)


def test_exception_hierarchy():
    """测试异常继承关系"""
    # 所有异常都应该继承自XSOCAgentError
    assert issubclass(ConfigError, XSOCAgentError)
    assert issubclass(LLMServiceError, XSOCAgentError)
    assert issubclass(AgentError, XSOCAgentError)
    assert issubclass(ToolError, XSOCAgentError)
    assert issubclass(EventError, XSOCAgentError)
    assert issubclass(APIError, XSOCAgentError)

    # 子类继承关系
    assert issubclass(LLMAPIKeyError, LLMServiceError)
    assert issubclass(AgentNotFoundError, AgentError)
    assert issubclass(ToolNotFoundError, ToolError)
    assert issubclass(EventNotFoundError, EventError)
    assert issubclass(APIAuthenticationError, APIError)

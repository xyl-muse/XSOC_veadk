"""事件研判专家智能体单元测试"""
import pytest
import json
from unittest.mock import AsyncMock, MagicMock
from agents.investigation_agent import InvestigationAgent
from schemas.security_event import SecurityEvent, EventStatus


class TestInvestigationAgent:
    """事件研判专家智能体测试类"""

    @pytest.fixture
    def agent(self):
        """创建测试用的智能体实例"""
        # 直接配置模型参数，避免依赖环境变量
        agent = InvestigationAgent(
            model_name="mock-model",
            model_provider="mock-provider",
            model_api_base="http://localhost:8080/api/v1",
            model_api_key="mock-api-key"
        )
        agent.call_tool = AsyncMock()
        agent.send_to_agent = AsyncMock()
        agent.context = MagicMock()
        agent.context.save_event = AsyncMock()
        agent.llm = MagicMock()
        agent.llm.chat = AsyncMock()
        agent.logger = MagicMock()
        return agent

    @pytest.mark.asyncio
    async def test_investigation_agent_initialization(self, agent):
        """测试智能体初始化"""
        assert agent.name == "investigation_agent"
        assert agent.display_name == "事件研判专家"
        assert "安全事件真实性研判" in agent.description

    @pytest.mark.asyncio
    async def test_investigation_agent_run_with_alert1(self, agent):
        """测试alert1的处理（主机失陷活动）"""
        # 准备测试数据
        with open("docs&data_demo/alert_demo/alert3.json", "r", encoding="utf-8") as f:
            alert1 = json.load(f)

        event_data = {
            "event_id": alert1["uuId"],
            "event_type": "server_security",
            "source": "xdr_api",
            "raw_data": alert1
        }

        # 设置工具调用返回结果
        agent.call_tool.side_effect = [
            {"is_malicious": True, "risk_level": "high", "tags": ["malicious", "botnet"]},
            {"hostname": "10.48.99.152", "os": "Windows Server", "vulnerabilities": ["CVE-2024-xxxx"]},
            {"alert_level": "high", "description": alert1["description"]}
        ]

        # 预期返回结果
        agent.llm.chat.return_value.content = "真实事件：主机失陷活动，包含执行、探测、防御规避、持久化、反弹Shell等风险行为"

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert1["uuId"]
        assert result["status"] == EventStatus.TRACING.value
        assert "真实事件" in result["result"]

    @pytest.mark.asyncio
    async def test_investigation_agent_run_with_alert2(self, agent):
        """测试alert2的处理（FastJson漏洞攻击）"""
        # 准备测试数据
        with open("docs&data_demo/alert_demo/alert2.json", "r", encoding="utf-8") as f:
            alert2 = json.load(f)

        event_data = {
            "event_id": alert2["uuId"],
            "event_type": "network_attack",
            "source": "xdr_api",
            "raw_data": alert2
        }

        # 设置工具调用返回结果
        agent.call_tool.side_effect = [
            {"is_malicious": True, "risk_level": "high", "tags": ["malicious", "vulnerability"]},
            {"hostname": "172.27.128.237", "os": "Linux", "vulnerabilities": ["CVE-2024-xxxx"]},
            {"alert_level": "high", "description": alert2["description"]}
        ]

        # 预期返回结果
        agent.llm.chat.return_value.content = "真实事件：FastJson服务端请求伪造漏洞攻击，GPT预研判结果为真实攻击成功"

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert2["uuId"]
        assert result["status"] == EventStatus.TRACING.value
        assert "真实事件" in result["result"]

    @pytest.mark.asyncio
    async def test_investigation_agent_run_with_alert3(self, agent):
        """测试alert3的处理（普通病毒感染）"""
        # 准备测试数据
        with open("docs&data_demo/alert_demo/alert3.json", "r", encoding="utf-8") as f:
            alert3 = json.load(f)

        event_data = {
            "event_id": alert3["uuId"],
            "event_type": "endpoint_security",
            "source": "xdr_api",
            "raw_data": alert3
        }

        # 设置工具调用返回结果
        agent.call_tool.side_effect = [
            {"is_malicious": True, "risk_level": "high", "tags": ["malicious", "virus"]},
            {"hostname": "10.48.97.39", "os": "Windows", "vulnerabilities": ["CVE-2024-xxxx"]},
            {"alert_level": "high", "description": alert3["description"]}
        ]

        # 预期返回结果
        agent.llm.chat.return_value.content = "真实事件：普通病毒感染，包含执行、探测、防御规避、持久化等风险行为"

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert3["uuId"]
        assert result["status"] == EventStatus.TRACING.value
        assert "真实事件" in result["result"]

    @pytest.mark.asyncio
    async def test_investigation_agent_extract_clues(self, agent):
        """测试从研判结果中提取攻击线索"""
        # 测试数据
        judgement_text = """真实事件：
攻击源IP：1.2.3.4
目标资产：10.48.99.152
攻击时间：2024-03-29 10:30:00
攻击类型：主机失陷活动
关键证据：包含执行、探测、防御规避、持久化、反弹Shell等风险行为"""

        clues = agent.extract_clues(judgement_text)

        assert len(clues) == 5
        assert "攻击源IP：1.2.3.4" in clues
        assert "目标资产：10.48.99.152" in clues
        assert "攻击时间：2024-03-29 10:30:00" in clues
        assert "攻击类型：主机失陷活动" in clues
        assert "关键证据：包含执行、探测、防御规避、持久化、反弹Shell等风险行为" in clues

    @pytest.mark.asyncio
    async def test_check_false_positive_rules(self, agent):
        """测试误报规则库匹配"""
        # 测试白名单IP误报
        event2 = SecurityEvent.from_input({
            "event_id": "1002",
            "event_type": "network_attack",
            "raw_data": {"description": "Internal network communication", "attack_source_ip": "10.0.0.10"}
        })

        # 设置工具调用返回结果
        agent.call_tool.return_value = {"reason": "攻击源IP属于私有IP段(10.0.0.0/8)，判断为误报"}

        false_positive_result2 = await agent._check_false_positive_rules(event2)
        assert false_positive_result2 is not None
        assert "私有IP段" in false_positive_result2

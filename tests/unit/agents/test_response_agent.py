"""风险处置专家智能体单元测试"""
import pytest
import json
from unittest.mock import AsyncMock, MagicMock
from agents.response_agent import ResponseAgent
from schemas.security_event import SecurityEvent, EventStatus


class TestResponseAgent:
    """风险处置专家智能体测试类"""

    @pytest.fixture
    def agent(self):
        """创建测试用的智能体实例"""
        agent = ResponseAgent(
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
    async def test_response_agent_initialization(self, agent):
        """测试智能体初始化"""
        assert agent.name == "response_agent"
        assert agent.display_name == "风险处置专家"
        assert "风险评估" in agent.description
        assert agent.enable_supervisor == False  # 默认未启用HITL

    @pytest.mark.asyncio
    async def test_response_agent_run_with_alert1(self, agent):
        """测试alert1的处理（主机失陷活动）"""
        # 准备测试数据
        with open("docs&data_demo/alert_demo/alert3.json", "r", encoding="utf-8") as f:
            alert1 = json.load(f)

        event_data = {
            "event_id": alert1["uuId"],
            "event_type": "server_security",
            "source": "xdr_api",
            "raw_data": alert1,
            "attack_source_ip": "192.168.1.100",
            "target_asset_ip": alert1["hostIp"]
        }

        # 设置工具调用返回结果
        agent.call_tool.side_effect = [
            {"status": "success", "message": "IP封禁成功"},
            {"status": "success", "message": "告警通知成功"}
        ]

        # 预期返回结果
        agent.llm.chat.return_value.content = "风险等级：高危，影响范围：中等，资产重要性：高"

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert1["uuId"]
        assert result["status"] == EventStatus.VISUALIZING.value
        assert "处置成功" in result["result"]

    @pytest.mark.asyncio
    async def test_response_agent_run_with_alert2(self, agent):
        """测试alert2的处理（FastJson漏洞攻击）"""
        # 准备测试数据
        with open("docs&data_demo/alert_demo/alert2.json", "r", encoding="utf-8") as f:
            alert2 = json.load(f)

        event_data = {
            "event_id": alert2["uuId"],
            "event_type": "network_attack",
            "source": "xdr_api",
            "raw_data": alert2,
            "attack_source_ip": "10.0.0.100",
            "target_asset_ip": alert2.get("hostIp", "172.27.128.237")
        }

        # 设置工具调用返回结果
        agent.call_tool.side_effect = [
            {"status": "success", "message": "IP封禁成功"},
            {"status": "success", "message": "告警通知成功"}
        ]

        # 预期返回结果
        agent.llm.chat.return_value.content = "风险等级：高危，影响范围：中等，资产重要性：高"

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert2["uuId"]
        assert result["status"] == EventStatus.VISUALIZING.value
        assert "处置成功" in result["result"]

    @pytest.mark.asyncio
    async def test_response_agent_run_with_alert3(self, agent):
        """测试alert3的处理（普通病毒感染）"""
        # 准备测试数据
        with open("docs&data_demo/alert_demo/alert1.json", "r", encoding="utf-8") as f:
            alert3 = json.load(f)

        event_data = {
            "event_id": alert3["state"]["uuId"],
            "event_type": "endpoint_security",
            "source": "xdr_api",
            "raw_data": alert3["state"],
            "attack_source_ip": "172.16.0.100",
            "target_asset_ip": alert3["state"].get("hostIp", "10.48.97.39")
        }

        # 设置工具调用返回结果
        agent.call_tool.side_effect = [
            {"status": "success", "message": "终端隔离成功"},
            {"status": "success", "message": "告警通知成功"}
        ]

        # 预期返回结果
        agent.llm.chat.return_value.content = "风险等级：中等，影响范围：小，资产重要性：中等"

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert3["state"]["uuId"]
        assert result["status"] == EventStatus.VISUALIZING.value
        assert "处置成功" in result["result"]

    @pytest.mark.asyncio
    async def test_response_agent_risk_assessment(self, agent):
        """测试风险评估功能"""
        # 测试数据
        event_data = {
            "event_id": "1001",
            "event_type": "network_attack",
            "source": "xdr_api",
            "raw_data": {
                "incidentSeverity": 3,
                "riskTag": ["执行", "持久化"],
                "attack_source_ip": "192.168.1.100"
            }
        }

        security_event = SecurityEvent.from_input(event_data)

        # 设置工具调用返回结果
        agent.call_tool.return_value = {
            "risk_level": "high",
            "impact_range": "medium",
            "asset_importance": "high"
        }

        risk_assessment = await agent._assess_risk(security_event)

        assert risk_assessment["risk_level"] == "high"
        assert risk_assessment["impact_range"] == "medium"
        assert risk_assessment["asset_importance"] == "high"

    @pytest.mark.asyncio
    async def test_response_agent_response_strategy(self, agent):
        """测试处置策略制定功能"""
        event_data = {
            "event_id": "1002",
            "event_type": "server_security",
            "source": "xdr_api",
            "raw_data": {
                "incidentSeverity": 4,
                "riskTag": ["执行", "持久化", "横向移动"],
                "attack_source_ip": "10.0.0.100"
            }
        }

        security_event = SecurityEvent.from_input(event_data)
        security_event.context["risk_assessment"] = {
            "risk_level": "critical",
            "impact_range": "large",
            "asset_importance": "high"
        }

        # 设置工具调用返回结果
        agent.call_tool.return_value = {
            "strategy_type": "comprehensive",
            "execution_steps": ["IP封禁", "终端隔离", "告警通知"],
            "expected_effect": "完全阻止攻击，防止进一步扩散"
        }

        response_strategy = await agent._develop_response_strategy(security_event)

        assert response_strategy["strategy_type"] == "comprehensive"
        assert "IP封禁" in response_strategy["execution_steps"]
        assert "终端隔离" in response_strategy["execution_steps"]

    @pytest.mark.asyncio
    async def test_response_agent_execute_response(self, agent):
        """测试处置操作执行功能"""
        event_data = {
            "event_id": "1003",
            "event_type": "endpoint_security",
            "source": "xdr_api",
            "raw_data": {
                "incidentSeverity": 2,
                "riskTag": ["执行"],
                "attack_source_ip": "172.16.0.100"
            }
        }

        security_event = SecurityEvent.from_input(event_data)
        security_event.context["risk_assessment"] = {
            "risk_level": "medium",
            "impact_range": "small",
            "asset_importance": "normal"
        }

        security_event.context["response_strategy"] = {
            "strategy_type": "moderate",
            "execution_steps": ["白名单管理", "告警通知"],
            "expected_effect": "监控攻击，防止进一步扩散"
        }

        agent.call_tool.side_effect = [
            {"status": "success", "message": "白名单管理成功"},
            {"status": "success", "message": "告警通知成功"}
        ]

        execution_result = await agent._execute_response(security_event)

        assert execution_result["status"] == "success"
        assert len(execution_result["operations"]) == 2
        assert any(operation["operation"] == "白名单管理" for operation in execution_result["operations"])

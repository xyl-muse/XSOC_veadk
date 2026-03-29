"""数据可视化专家智能体单元测试"""
import pytest
import json
from unittest.mock import AsyncMock, MagicMock
from agents.visualization_agent import VisualizationAgent
from schemas.security_event import SecurityEvent, EventStatus


class TestVisualizationAgent:
    """数据可视化专家智能体测试类"""

    @pytest.fixture
    def agent(self):
        """创建测试用的智能体实例"""
        agent = VisualizationAgent(
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
    async def test_visualization_agent_initialization(self, agent):
        """测试智能体初始化"""
        assert agent.name == "visualization_agent"
        assert agent.display_name == "数据可视化专家"
        assert "事件报告生成" in agent.description

    @pytest.mark.asyncio
    async def test_visualization_agent_run_with_alert1(self, agent):
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
            {"status": "success", "message": "XDR数据回写成功"},
            {"status": "success", "message": "钉钉AI表格同步成功"}
        ]

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert1["uuId"]
        assert result["status"] == EventStatus.ARCHIVED.value
        assert "事件报告生成和数据同步成功" in result["result"]

    @pytest.mark.asyncio
    async def test_visualization_agent_run_with_alert2(self, agent):
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
            {"status": "success", "message": "XDR数据回写成功"},
            {"status": "success", "message": "钉钉AI表格同步成功"}
        ]

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert2["uuId"]
        assert result["status"] == EventStatus.ARCHIVED.value
        assert "事件报告生成和数据同步成功" in result["result"]

    @pytest.mark.asyncio
    async def test_visualization_agent_run_with_alert3(self, agent):
        """测试alert3的处理（普通病毒感染）"""
        # 准备测试数据
        with open("docs&data_demo/alert_demo/alert1.json", "r", encoding="utf-8") as f:
            alert3 = json.load(f)

        event_data = {
            "event_id": alert3["state"]["uuId"],
            "event_type": "endpoint_security",
            "source": "xdr_api",
            "raw_data": alert3["state"]
        }

        # 设置工具调用返回结果
        agent.call_tool.side_effect = [
            {"status": "success", "message": "XDR数据回写成功"},
            {"status": "success", "message": "钉钉AI表格同步成功"}
        ]

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert3["state"]["uuId"]
        assert result["status"] == EventStatus.ARCHIVED.value
        assert "事件报告生成和数据同步成功" in result["result"]

    @pytest.mark.asyncio
    async def test_visualization_agent_generate_report(self, agent):
        """测试事件报告生成功能"""
        event_data = {
            "event_id": "1001",
            "event_type": "server_security",
            "source": "xdr_api",
            "raw_data": {
                "incidentSeverity": 3,
                "riskTag": ["执行", "持久化"],
                "attack_source_ip": "192.168.1.100"
            }
        }

        security_event = SecurityEvent.from_input(event_data)
        security_event.context["risk_assessment"] = {
            "risk_level": "high",
            "impact_range": "medium",
            "asset_importance": "high"
        }

        security_event.context["response_strategy"] = {
            "strategy_type": "aggressive",
            "execution_steps": ["IP封禁", "告警通知"],
            "expected_effect": "阻止攻击，防止进一步扩散"
        }

        security_event.context["execution_result"] = {
            "status": "success",
            "operations": [
                {"operation": "IP封禁", "status": "success"},
                {"operation": "告警通知", "status": "success"}
            ]
        }

        report = agent._generate_event_report(security_event)

        assert "安全事件报告" in report
        assert "事件基本信息" in report
        assert "事件处理过程" in report
        assert "事件详情" in report

"""溯源分析专家智能体单元测试"""
import pytest
import json
from unittest.mock import AsyncMock, MagicMock
from agents.tracing_agent import TracingAgent
from schemas.security_event import SecurityEvent, EventStatus


class TestTracingAgent:
    """溯源分析专家智能体测试类"""

    @pytest.fixture
    def agent(self):
        """创建测试用的智能体实例"""
        # 直接配置模型参数，避免依赖环境变量
        agent = TracingAgent(
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
    async def test_tracing_agent_initialization(self, agent):
        """测试智能体初始化"""
        assert agent.name == "tracing_agent"
        assert agent.display_name == "溯源分析专家"
        assert "深度调查" in agent.description

    @pytest.mark.asyncio
    async def test_tracing_agent_run_with_alert1(self, agent):
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
            {"entry_point": "远程代码执行漏洞", "lateral_movement": ["10.48.99.152 -> 10.48.99.153"], "privilege_escalation": "本地权限提升", "c2_servers": ["1.2.3.4"]},
            {"source_ip": "1.2.3.4", "target_ip": "10.48.99.152", "protocol": "TCP", "port": "443"},
            {"process_name": "malware.exe", "pid": "1234", "command_line": "powershell.exe -ExecutionPolicy Bypass"},
        ]

        # 预期返回结果
        agent.llm.chat.return_value.content = """攻击路径：
1. 入口点：远程代码执行漏洞（CVE-2024-xxxx）
2. 横向移动：10.48.99.152 -> 10.48.99.153
3. 权限提升：本地权限提升
4. C2服务器：1.2.3.4

攻击工具：PowerShell脚本
技术手段：远程代码执行、横向移动、权限提升
恶意代码：malware.exe
"""

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert1["uuId"]
        assert result["status"] == EventStatus.RESPONDING.value
        assert "攻击路径" in result["result"]

    @pytest.mark.asyncio
    async def test_tracing_agent_run_with_alert2(self, agent):
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
            {"entry_point": "FastJson漏洞", "lateral_movement": [], "privilege_escalation": "远程代码执行", "c2_servers": ["5.6.7.8"]},
            {"source_ip": "5.6.7.8", "target_ip": "172.27.128.237", "protocol": "HTTP", "port": "8080"},
            {"process_name": "java.exe", "pid": "5678", "command_line": "java -jar malicious.jar"},
        ]

        # 预期返回结果
        agent.llm.chat.return_value.content = """攻击路径：
1. 入口点：FastJson漏洞（CVE-2024-xxxx）
2. 横向移动：无
3. 权限提升：远程代码执行
4. C2服务器：5.6.7.8

攻击工具：Java恶意代码
技术手段：远程代码执行
恶意代码：malicious.jar
"""

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert2["uuId"]
        assert result["status"] == EventStatus.RESPONDING.value
        assert "FastJson" in result["result"]

    @pytest.mark.asyncio
    async def test_tracing_agent_run_with_alert3(self, agent):
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
            {"entry_point": "恶意软件下载", "lateral_movement": ["10.48.97.39 -> 10.48.97.40"], "privilege_escalation": "本地权限提升", "c2_servers": ["9.10.11.12"]},
            {"source_ip": "9.10.11.12", "target_ip": "10.48.97.39", "protocol": "HTTP", "port": "80"},
            {"process_name": "virus.exe", "pid": "9012", "command_line": "virus.exe -install"},
        ]

        # 预期返回结果
        agent.llm.chat.return_value.content = """攻击路径：
1. 入口点：恶意软件下载
2. 横向移动：10.48.97.39 -> 10.48.97.40
3. 权限提升：本地权限提升
4. C2服务器：9.10.11.12

攻击工具：恶意软件
技术手段：恶意软件下载、横向移动、权限提升
恶意代码：virus.exe
"""

        # 执行测试
        result = await agent.run(event_data)

        # 断言结果
        assert result["event_id"] == alert3["state"]["uuId"]
        assert result["status"] == EventStatus.RESPONDING.value
        assert "恶意软件" in result["result"]

    @pytest.mark.asyncio
    async def test_tracing_agent_extract_attack_clues(self, agent):
        """测试从溯源结果中提取攻击线索"""
        # 测试数据
        tracing_result = """攻击路径：
1. 入口点：远程代码执行漏洞（CVE-2024-xxxx）
2. 横向移动：10.48.99.152 -> 10.48.99.153
3. 权限提升：本地权限提升
4. C2服务器：1.2.3.4

攻击工具：PowerShell脚本
技术手段：远程代码执行、横向移动、权限提升
恶意代码：malware.exe
"""

        attack_clues = agent.extract_attack_clues(tracing_result)

        assert len(attack_clues["attack_tools"]) >= 1
        assert len(attack_clues["attack_techniques"]) >= 1
        assert len(attack_clues["malicious_code"]) >= 1
        assert len(attack_clues["c2_servers"]) >= 1
        assert "PowerShell" in str(attack_clues["attack_tools"])
        assert "malware.exe" in str(attack_clues["malicious_code"])

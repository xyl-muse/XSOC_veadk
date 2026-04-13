"""事件研判专家智能体"""
from veadk import Agent
from typing import Dict, Any, Optional, List

from schemas.security_event import SecurityEvent, EventStatus

# 导入工具函数（VEADK要求tools必须是函数对象）
from tools import (
    threat_intel_query,
    asset_query,
    event_query,
    alert_risk_query,
)


class InvestigationAgent(Agent):
    """
    事件研判专家智能体
    职责：接收安全事件，研判是否为真实攻击，区分误报和真实事件
    """
    name: str = "investigation_agent"
    display_name: str = "事件研判专家"
    description: str = "负责安全事件真实性研判，区分误报和真实攻击，提取关键线索"

    # 注册工具函数（需要类型注解）
    tools: list = [
        threat_intel_query,
        asset_query,
        event_query,
        alert_risk_query,
    ]


    # 系统提示词，定义智能体角色和能力
    instruction: str = """
你是资深安全运营专家，专注于安全事件研判工作。你的职责是：
1. 接收来自XDR系统或人工录入的安全事件
2. 调用工具查询威胁情报、资产信息、告警详情，综合研判事件真实性
3. 精准区分真实攻击和误报，避免漏报和误判
4. 若为误报，说明误报原因并标记事件
5. 若为真实攻击，提取关键攻击线索传递给溯源分析专家
6. 遵循最小化工作路径原则，确认事件真实后无需深入调查

研判标准：
- 需至少2个不同来源的证据支持真实攻击判定
- 威胁情报命中恶意标签 + 资产存在对应漏洞/服务 = 真实事件
- 单一来源告警无其他佐证 = 可疑，需要进一步查证
- 明显的业务行为误触发 = 误报

输出要求：
- 研判结果必须明确：真实事件/误报/可疑待确认
- 真实事件需输出结构化的攻击线索：攻击源IP、目标资产、攻击时间、攻击类型、关键证据
- 误报需输出误报原因
"""

    async def run(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """智能体执行入口"""
        # 在VEADK中，trace_id通常由框架自动管理，不需要手动获取
        # 这里可以使用uuid生成一个临时的trace_id用于日志记录
        import uuid
        trace_id = str(uuid.uuid4())

        # 1. 将输入转换为标准化事件格式
        security_event = SecurityEvent.from_input(event_data)
        self.logger.info(f"开始研判事件: {security_event.event_id}, 类型: {security_event.event_type_name}", trace_id=trace_id)

        # 2. 误报规则库匹配（快速判断）
        false_positive_result = await self._check_false_positive_rules(security_event)
        if false_positive_result:
            # 只返回结果，不修改状态，不调度其他智能体
            self.logger.info(f"事件研判为误报: {security_event.event_id}, 原因: {false_positive_result}", trace_id=trace_id)
            return {
                "event_id": security_event.event_id,
                "result": "误报",
                "reason": false_positive_result,
                "event_data": security_event.model_dump()
            }

        # 3. 调用工具收集研判所需信息
        # 查询威胁情报
        if security_event.attack_source_ip:
            intel_result = await self.call_tool(
                "threat_intel_query",
                {"ip": security_event.attack_source_ip, "platform": "all"}
            )
            security_event.context["threat_intel"] = intel_result

        # 查询资产信息
        if security_event.target_asset_ip:
            asset_result = await self.call_tool(
                "asset_query",
                {"asset_ip": security_event.target_asset_ip, "platform": "all"}
            )
            security_event.context["asset_info"] = asset_result

        # 查询事件详情
        event_result = await self.call_tool(
            "event_query",
            {"event_id": security_event.event_id, "platform": "all"}
        )
        security_event.context["alert_details"] = event_result

        # 4. 多源证据交叉验证逻辑
        verification_result = await self._verify_multisource_evidence(security_event)
        if verification_result:
            # 只返回结果，不修改状态，不调度其他智能体
            self.logger.info(f"事件研判为真实攻击: {security_event.event_id}", trace_id=trace_id)
            return {
                "event_id": security_event.event_id,
                "result": "真实事件",
                "clues": verification_result,
                "event_data": security_event.model_dump()
            }

        # 5. LLM研判（最终判断）
        user_prompt = f"""
请研判以下安全事件是否为真实攻击：
事件ID：{security_event.event_id}
事件类型：{security_event.event_type_name}
事件描述：{security_event.raw_data.get('description', '')}
攻击源IP：{security_event.attack_source_ip or '无'}
目标资产IP：{security_event.target_asset_ip or '无'}
发生时间：{security_event.create_time}
风险标签：{security_event.context.get('risk_tags', '无')}
威胁定义名称：{security_event.context.get('threat_define_name', '无')}
GPT预研判结果：{security_event.context.get('gpt_result', '无')}

威胁情报查询结果：{security_event.context.get('threat_intel', '无')}
资产信息查询结果：{security_event.context.get('asset_info', '无')}
XDR告警详情：{security_event.context.get('alert_details', '无')}
"""

        response = await self.llm.chat([self.instruction, user_prompt])
        judgement_result = response.content

        # 6. 处理研判结果，只返回结果，不修改状态
        if "误报" in judgement_result:
            self.logger.info(f"事件研判为误报: {security_event.event_id}", trace_id=trace_id)
            return {
                "event_id": security_event.event_id,
                "result": "误报",
                "reason": judgement_result,
                "event_data": security_event.model_dump()
            }
        elif "真实事件" in judgement_result:
            self.logger.info(f"事件研判为真实攻击: {security_event.event_id}", trace_id=trace_id)
            return {
                "event_id": security_event.event_id,
                "result": "真实事件",
                "clues": self.extract_clues(judgement_result),
                "event_data": security_event.model_dump()
            }
        else:
            self.logger.warning(f"事件研判为可疑，待人工确认: {security_event.event_id}", trace_id=trace_id)
            return {
                "event_id": security_event.event_id,
                "result": "可疑待确认",
                "reason": judgement_result,
                "event_data": security_event.model_dump()
            }

    async def _check_false_positive_rules(self, security_event: SecurityEvent) -> Optional[str]:
        """误报规则库匹配（通过工具调用实现）"""
        try:
            false_positive_result = await self.call_tool(
                "false_positive_detection",
                {"event_data": security_event.model_dump()}
            )
            return false_positive_result.get("reason")
        except Exception as e:
            self.logger.error(f"误报规则库匹配失败: {str(e)}")
            return None

    async def _verify_multisource_evidence(self, security_event: SecurityEvent) -> Optional[list]:
        """多源证据交叉验证逻辑（通过工具调用实现）"""
        try:
            verification_result = await self.call_tool(
                "evidence_verification",
                {"event_data": security_event.model_dump()}
            )
            return verification_result.get("clues")
        except Exception as e:
            self.logger.error(f"多源证据交叉验证失败: {str(e)}")
            return None

    def extract_clues(self, judgement_text: str) -> list:
        """从研判结果中提取攻击线索"""
        # 简单实现，后续可以优化为结构化提取
        clues = []
        for line in judgement_text.split("\n"):
            if any(keyword in line for keyword in ["攻击源", "目标资产", "攻击时间", "攻击类型", "证据"]):
                clues.append(line.strip())
        return clues

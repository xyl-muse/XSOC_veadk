"""事件研判专家智能体"""
from veadk import Agent
from typing import Dict, Any, Optional

from schemas.security_event import SecurityEvent, EventStatus


class InvestigationAgent(Agent):
    """
    事件研判专家智能体
    职责：接收安全事件，研判是否为真实攻击，区分误报和真实事件
    """
    name: str = "investigation_agent"
    display_name: str = "事件研判专家"
    description: str = "负责安全事件真实性研判，区分误报和真实攻击，提取关键线索"

    # 模型配置
    model_name: str = "iflow-rome-30ba3b"
    model_provider: str = "openai"
    model_api_base: str = "https://apis.iflow.cn/v1"
    model_api_key: str = "sk-3e57cc3cafa15e65f40c5b2a6b708a68"

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
        false_positive_result = self._check_false_positive_rules(security_event)
        if false_positive_result:
            security_event.status = EventStatus.FALSE_POSITIVE
            security_event.process_history.append({
                "stage": "investigation",
                "stage_name": "事件研判",
                "result": "误报",
                "reason": false_positive_result
            })
            self.logger.info(f"事件研判为误报: {security_event.event_id}, 原因: {false_positive_result}", trace_id=trace_id)
            await self.send_to_agent("visualization_agent", security_event.model_dump())
            await self.context.save_event(security_event.event_id, security_event.model_dump())
            return {
                "event_id": security_event.event_id,
                "status": security_event.status.value,
                "status_name": security_event.status_name,
                "result": "误报",
                "reason": false_positive_result
            }

        # 3. 调用工具收集研判所需信息
        # 查询威胁情报
        if security_event.attack_source_ip:
            intel_result = await self.call_tool(
                "threat_intel_query",
                {"ip": security_event.attack_source_ip}
            )
            security_event.context["threat_intel"] = intel_result

        # 查询资产信息
        if security_event.target_asset_ip:
            asset_result = await self.call_tool(
                "asset_query",
                {"ip": security_event.target_asset_ip}
            )
            security_event.context["asset_info"] = asset_result

        # 查询XDR事件详情
        xdr_result = await self.call_tool(
            "xdr_event_query",
            {"event_id": security_event.event_id}
        )
        security_event.context["alert_details"] = xdr_result

        # 4. 多源证据交叉验证逻辑
        verification_result = self._verify_multisource_evidence(security_event)
        if verification_result:
            security_event.status = EventStatus.TRACING
            security_event.process_history.append({
                "stage": "investigation",
                "stage_name": "事件研判",
                "result": "真实事件",
                "clues": verification_result
            })
            self.logger.info(f"事件研判为真实攻击: {security_event.event_id}", trace_id=trace_id)
            await self.send_to_agent("tracing_agent", security_event.model_dump())
            await self.context.save_event(security_event.event_id, security_event.model_dump())
            return {
                "event_id": security_event.event_id,
                "status": security_event.status.value,
                "status_name": security_event.status_name,
                "result": "真实事件",
                "clues": verification_result
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

        # 6. 处理研判结果
        if "误报" in judgement_result:
            security_event.status = EventStatus.FALSE_POSITIVE
            security_event.process_history.append({
                "stage": "investigation",
                "stage_name": "事件研判",
                "result": "误报",
                "reason": judgement_result
            })
            self.logger.info(f"事件研判为误报: {security_event.event_id}", trace_id=trace_id)
            await self.send_to_agent("visualization_agent", security_event.model_dump())
        elif "真实事件" in judgement_result:
            security_event.status = EventStatus.TRACING
            security_event.process_history.append({
                "stage": "investigation",
                "stage_name": "事件研判",
                "result": "真实事件",
                "clues": self.extract_clues(judgement_result)
            })
            self.logger.info(f"事件研判为真实攻击: {security_event.event_id}", trace_id=trace_id)
            await self.send_to_agent("tracing_agent", security_event.model_dump())
        else:
            security_event.status = EventStatus.PENDING_MANUAL_CONFIRM
            security_event.process_history.append({
                "stage": "investigation",
                "stage_name": "事件研判",
                "result": "可疑待确认",
                "reason": judgement_result
            })
            self.logger.warning(f"事件研判为可疑，待人工确认: {security_event.event_id}", trace_id=trace_id)

        # 7. 保存事件状态
        await self.context.save_event(security_event.event_id, security_event.model_dump())

        return {
            "event_id": security_event.event_id,
            "status": security_event.status.value,
            "status_name": security_event.status_name,
            "result": judgement_result
        }

    def _check_false_positive_rules(self, security_event: SecurityEvent) -> Optional[str]:
        """误报规则库匹配"""
        raw_data = security_event.raw_data

        # 1. 业务行为误报规则（暂时禁用，因为XDR事件原始数据可能包含相关关键词）
        # business_keywords = ["test", "debug", "monitor", "health", "check"]
        # if any(keyword in str(raw_data).lower() for keyword in business_keywords):
        #     return "包含业务行为关键词(test/debug/monitor/health/check)，判断为误报"

        # 2. 白名单匹配规则
        white_list_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        if security_event.attack_source_ip:
            from ipaddress import ip_address, IPv4Network
            try:
                src_ip = ip_address(security_event.attack_source_ip)
                for network in white_list_ips:
                    if src_ip in IPv4Network(network):
                        return f"攻击源IP属于私有IP段({network})，判断为误报"
            except:
                pass

        # 3. 高频告警规则（需要接入告警频率数据）
        # TODO: 接入告警频率API

        # 4. 明显误报模式匹配
        if "正常流量" in str(raw_data) or "业务测试" in str(raw_data):
            return "事件类型包含正常流量或业务测试，判断为误报"

        # 5. GPT预研判结果为误报
        gpt_result = security_event.context.get("gpt_result", "")
        if isinstance(gpt_result, str) and gpt_result.lower() == "误报":
            return "GPT预研判结果为误报"
        elif isinstance(gpt_result, int) and gpt_result == 0:
            return "GPT预研判结果为误报"

        return None

    def _verify_multisource_evidence(self, security_event: SecurityEvent) -> Optional[list]:
        """多源证据交叉验证逻辑"""
        clues = []

        # 1. 威胁情报命中恶意标签 + 资产存在对应漏洞/服务
        threat_intel = security_event.context.get("threat_intel", {})
        asset_info = security_event.context.get("asset_info", {})
        risk_tags = security_event.context.get("risk_tags", [])

        if threat_intel.get("is_malicious") or threat_intel.get("risk_level") in ["high", "critical"]:
            if "vulnerability" in str(asset_info).lower() or "service" in str(asset_info).lower() or len(risk_tags) > 0:
                clues.append("威胁情报命中恶意标签，资产存在对应漏洞/服务")

        # 2. 威胁情报 + XDR告警详情验证
        alert_details = security_event.context.get("alert_details", {})
        if threat_intel.get("is_malicious") and len(str(alert_details)) > 50:
            clues.append("威胁情报命中恶意标签，XDR告警详情包含攻击线索")

        # 3. 风险标签 + 攻击源IP验证
        if len(risk_tags) > 0 and security_event.attack_source_ip:
            clues.append(f"存在风险标签({','.join(risk_tags)})，攻击源IP({security_event.attack_source_ip})可疑")

        # 4. 需要至少2个不同来源的证据支持真实攻击判定
        if len(clues) >= 2:
            return clues

        return None

    def extract_clues(self, judgement_text: str) -> list:
        """从研判结果中提取攻击线索"""
        # 简单实现，后续可以优化为结构化提取
        clues = []
        for line in judgement_text.split("\n"):
            if any(keyword in line for keyword in ["攻击源", "目标资产", "攻击时间", "攻击类型", "证据"]):
                clues.append(line.strip())
        return clues

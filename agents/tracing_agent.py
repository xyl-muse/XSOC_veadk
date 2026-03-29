"""溯源分析专家智能体"""
from veadk import Agent
from typing import Dict, Any, Optional
from schemas.security_event import SecurityEvent, EventStatus


class TracingAgent(Agent):
    """
    溯源分析专家智能体
    职责：对真实攻击事件进行深度调查，还原攻击路径，提取攻击线索
    """
    name: str = "tracing_agent"
    display_name: str = "溯源分析专家"
    description: str = "负责对真实攻击事件进行深度调查，还原攻击路径，提取攻击线索"

    # 智能体系统提示词
    instruction: str = """
你是资深安全溯源分析专家，专注于安全事件的深度调查和攻击路径还原工作。你的职责是：
1. 接收来自事件研判专家的真实攻击事件和关键线索
2. 调用工具查询威胁情报、资产信息、攻击路径、网络流量等数据
3. 还原攻击者的攻击路径，包括入口点、横向移动、权限提升等阶段
4. 提取关键攻击信息，包括攻击工具、技术手段、恶意代码等
5. 生成详细的溯源分析报告，为风险处置提供依据
6. 遵循最小化工作路径原则，重点关注攻击路径还原和关键线索提取

输出要求：
- 溯源结果必须明确：攻击路径、入口点、横向移动、权限提升等
- 攻击线索需输出结构化的信息：攻击工具、技术手段、恶意代码、C2服务器等
- 生成详细的溯源分析报告，包括步骤、证据和结论
    """

    async def run(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """智能体执行入口"""
        import uuid
        trace_id = str(uuid.uuid4())

        # 1. 将输入转换为标准化事件格式
        security_event = SecurityEvent.from_input(event_data)
        self.logger.info(f"开始溯源分析事件: {security_event.event_id}, 类型: {security_event.event_type_name}", trace_id=trace_id)

        # 2. 调用工具收集溯源所需信息
        # 查询攻击路径
        if security_event.attack_source_ip:
            attack_path_result = await self.call_tool(
                "attack_path_query",
                {"ip": security_event.attack_source_ip}
            )
            security_event.context["attack_path"] = attack_path_result

        # 查询网络流量
        if security_event.attack_source_ip and security_event.target_asset_ip:
            network_traffic_result = await self.call_tool(
                "network_traffic_query",
                {"source_ip": security_event.attack_source_ip, "target_ip": security_event.target_asset_ip}
            )
            security_event.context["network_traffic"] = network_traffic_result

        # 查询进程实体
        if security_event.target_asset_ip:
            process_entity_result = await self.call_tool(
                "process_entity_query",
                {"ip": security_event.target_asset_ip}
            )
            security_event.context["process_entity"] = process_entity_result

        # 3. 还原攻击路径
        attack_path = self._reconstruct_attack_path(security_event)
        if attack_path:
            security_event.status = EventStatus.RESPONDING
            security_event.process_history.append({
                "stage": "tracing",
                "stage_name": "溯源分析",
                "result": "攻击路径还原成功",
                "attack_path": attack_path
            })
            self.logger.info(f"攻击路径还原成功: {security_event.event_id}", trace_id=trace_id)
            await self.send_to_agent("response_agent", security_event.model_dump())
            await self.context.save_event(security_event.event_id, security_event.model_dump())
            return {
                "event_id": security_event.event_id,
                "status": security_event.status.value,
                "status_name": security_event.status_name,
                "result": "攻击路径还原成功",
                "attack_path": attack_path
            }

        # 4. LLM溯源分析（最终判断）
        user_prompt = f"""
请对以下安全事件进行溯源分析：
事件ID：{security_event.event_id}
事件类型：{security_event.event_type_name}
事件描述：{security_event.raw_data.get('description', '')}
攻击源IP：{security_event.attack_source_ip or '无'}
目标资产IP：{security_event.target_asset_ip or '无'}
发生时间：{security_event.create_time}
风险标签：{security_event.context.get('risk_tags', '无')}
威胁定义名称：{security_event.context.get('threat_define_name', '无')}
研判结果：{security_event.context.get('judgement_result', '无')}

攻击路径查询结果：{security_event.context.get('attack_path', '无')}
网络流量查询结果：{security_event.context.get('network_traffic', '无')}
进程实体查询结果：{security_event.context.get('process_entity', '无')}
"""

        response = await self.llm.chat([self.instruction, user_prompt])
        tracing_result = response.content

        # 5. 处理溯源结果
        security_event.status = EventStatus.RESPONDING
        security_event.process_history.append({
            "stage": "tracing",
            "stage_name": "溯源分析",
            "result": "溯源分析完成",
            "tracing_result": tracing_result
        })
        self.logger.info(f"溯源分析完成: {security_event.event_id}", trace_id=trace_id)
        await self.send_to_agent("response_agent", security_event.model_dump())
        await self.context.save_event(security_event.event_id, security_event.model_dump())

        return {
            "event_id": security_event.event_id,
            "status": security_event.status.value,
            "status_name": security_event.status_name,
            "result": tracing_result
        }

    def _reconstruct_attack_path(self, security_event: SecurityEvent) -> Optional[dict]:
        """还原攻击路径"""
        attack_path = security_event.context.get("attack_path", {})

        if attack_path:
            # 提取攻击路径信息
            entry_point = attack_path.get("entry_point", "未知")
            lateral_movement = attack_path.get("lateral_movement", [])
            privilege_escalation = attack_path.get("privilege_escalation", "未知")
            c2_servers = attack_path.get("c2_servers", [])

            return {
                "entry_point": entry_point,
                "lateral_movement": lateral_movement,
                "privilege_escalation": privilege_escalation,
                "c2_servers": c2_servers
            }

        return None

    def extract_attack_clues(self, tracing_result: str) -> dict:
        """从溯源结果中提取攻击线索"""
        # 简单实现，后续可以优化为结构化提取
        attack_clues = {
            "attack_tools": [],
            "attack_techniques": [],
            "malicious_code": [],
            "c2_servers": []
        }

        for line in tracing_result.split("\n"):
            if any(keyword in line for keyword in ["攻击工具", "技术手段", "恶意代码", "C2服务器"]):
                # 简单解析攻击线索
                if "攻击工具" in line:
                    attack_clues["attack_tools"].append(line.strip())
                elif "技术手段" in line:
                    attack_clues["attack_techniques"].append(line.strip())
                elif "恶意代码" in line:
                    attack_clues["malicious_code"].append(line.strip())
                elif "C2服务器" in line:
                    attack_clues["c2_servers"].append(line.strip())

        return attack_clues

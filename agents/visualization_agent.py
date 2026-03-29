"""数据可视化专家智能体"""
from veadk import Agent
from typing import Dict, Any, Optional
from schemas.security_event import SecurityEvent, EventStatus
import json
from datetime import datetime


class VisualizationAgent(Agent):
    """
    数据可视化专家智能体
    职责：负责事件报告生成、XDR数据回写和钉钉AI表格同步
    """
    name: str = "visualization_agent"
    display_name: str = "数据可视化专家"
    description: str = "负责事件报告生成、XDR数据回写和钉钉AI表格同步"

    instruction: str = """
你是资深安全数据可视化专家，负责安全事件的报告生成、XDR系统数据回写和钉钉AI表格同步工作。你的职责是：
1. 接收风险处置专家发送的安全事件处置结果
2. 生成标准化的Markdown格式事件报告
3. 调用数据归档工具完成XDR系统数据回写
4. 调用数据归档工具同步事件数据到钉钉AI表格
5. 确保数据的完整性和准确性

输出要求：
- 事件报告必须包含完整的事件信息、处置过程和结果
- XDR数据回写必须确保成功
- 钉钉AI表格同步必须包含所有关键信息
    """

    async def run(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        import uuid
        trace_id = str(uuid.uuid4())

        security_event = SecurityEvent.from_input(event_data)
        self.logger.info(f"开始生成事件报告: {security_event.event_id}, 类型: {security_event.event_type_name}", trace_id=trace_id)

        event_report = self._generate_event_report(security_event)
        security_event.context["event_report"] = event_report

        xdr_archive_result = await self.call_tool("data_archive", {
            "archive_type": "xdr",
            "event_id": security_event.event_id,
            "event_data": security_event.model_dump()
        })
        security_event.context["xdr_archive_result"] = xdr_archive_result

        dingtalk_sync_result = await self.call_tool("data_archive", {
            "archive_type": "dingtalk",
            "event_id": security_event.event_id,
            "event_data": security_event.model_dump()
        })
        security_event.context["dingtalk_sync_result"] = dingtalk_sync_result

        security_event.status = EventStatus.ARCHIVED
        security_event.process_history.append({
            "stage": "visualization",
            "stage_name": "数据可视化",
            "result": "事件报告生成和数据同步成功",
            "event_report": event_report,
            "xdr_archive_result": xdr_archive_result,
            "dingtalk_sync_result": dingtalk_sync_result
        })

        self.logger.info(f"事件报告生成和数据同步成功: {security_event.event_id}", trace_id=trace_id)
        await self.context.save_event(security_event.event_id, security_event.model_dump())

        return {
            "event_id": security_event.event_id,
            "status": security_event.status.value,
            "status_name": security_event.status_name,
            "result": "事件报告生成和数据同步成功",
            "event_report": event_report,
            "xdr_archive_result": xdr_archive_result,
            "dingtalk_sync_result": dingtalk_sync_result
        }

    def _generate_event_report(self, security_event: SecurityEvent) -> str:
        """生成Markdown格式事件报告"""
        report = f"""# 安全事件报告\n\n## 事件基本信息\n"""
        report += f"- **事件ID**: {security_event.event_id}\n"
        report += f"- **事件类型**: {security_event.event_type_name}\n"
        report += f"- **事件状态**: {security_event.status_name}\n"
        report += f"- **来源**: {security_event.source_name}\n"
        report += f"- **创建时间**: {security_event.create_time}\n"
        report += f"- **优先级**: {security_event.priority_name}\n"
        report += f"- **攻击源IP**: {security_event.attack_source_ip or '未知'}\n"
        report += f"- **目标资产IP**: {security_event.target_asset_ip or '未知'}\n"

        report += f"\n## 事件处理过程\n"
        for history in security_event.process_history:
            report += f"### {history['stage_name']}\n"
            report += f"- **处理智能体**: {history['agent_name'] if 'agent_name' in history else '未知'}\n"
            report += f"- **处理状态**: {history['result']}\n"
            report += f"- **开始时间**: {history['start_time']}\n"
            if 'end_time' in history:
                report += f"- **结束时间**: {history['end_time']}\n"
            report += f"\n"

        report += f"\n## 事件详情\n"
        report += f"{json.dumps(security_event.raw_data, indent=2, ensure_ascii=False)}\n"

        report += f"\n## 报告生成时间\n"
        report += datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return report

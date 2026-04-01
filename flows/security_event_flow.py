"""
安全事件协作流程 - 父智能体编排器
基于VEADK父子智能体模式实现全流程闭环调度
"""
from veadk import Agent
from typing import Dict, Any, Optional, List, Callable
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, field
import asyncio
import uuid
import logging

from agents import (
    InvestigationAgent,
    TracingAgent,
    ResponseAgent,
    VisualizationAgent,
)
from schemas.security_event import SecurityEvent, EventStatus


# ============================================================================
# 状态机定义
# ============================================================================

class EventState(str, Enum):
    """事件状态枚举（与EventStatus保持一致）"""
    PENDING = "pending"
    VALIDATING = "validating"
    INVESTIGATING = "investigating"
    FALSE_POSITIVE = "false_positive"
    TRACING = "tracing"
    PROCESSING = "processing"
    VALIDATING_DISPOSAL = "validating_disposal"
    PENDING_APPROVAL = "pending_approval"
    EXECUTING_DISPOSAL = "executing_disposal"
    VERIFYING_DISPOSAL = "verifying_disposal"
    VISUALIZING = "visualizing"
    ARCHIVING = "archiving"
    COMPLETED = "completed"
    FAILED = "failed"
    CLOSED = "closed"


# 状态流转映射：定义每个状态可以转换到的下一状态
STATE_TRANSITIONS: Dict[EventState, List[EventState]] = {
    EventState.PENDING: [EventState.VALIDATING],
    EventState.VALIDATING: [EventState.INVESTIGATING, EventState.FAILED],
    EventState.INVESTIGATING: [EventState.FALSE_POSITIVE, EventState.TRACING, EventState.PENDING_APPROVAL],
    EventState.FALSE_POSITIVE: [EventState.VISUALIZING],
    EventState.TRACING: [EventState.PROCESSING, EventState.INVESTIGATING, EventState.PENDING_APPROVAL],
    EventState.PROCESSING: [EventState.VALIDATING_DISPOSAL],
    EventState.VALIDATING_DISPOSAL: [EventState.PENDING_APPROVAL, EventState.EXECUTING_DISPOSAL],
    EventState.PENDING_APPROVAL: [EventState.EXECUTING_DISPOSAL, EventState.VISUALIZING, EventState.CLOSED],
    EventState.EXECUTING_DISPOSAL: [EventState.VERIFYING_DISPOSAL, EventState.FAILED],
    EventState.VERIFYING_DISPOSAL: [EventState.VISUALIZING, EventState.FAILED],
    EventState.VISUALIZING: [EventState.ARCHIVING],
    EventState.ARCHIVING: [EventState.COMPLETED, EventState.FAILED],
    EventState.COMPLETED: [],
    EventState.FAILED: [EventState.PENDING_APPROVAL],  # 失败后可转人工审核
    EventState.CLOSED: [EventState.VISUALIZING],  # 关闭后仍需归档
}


@dataclass
class StateTransition:
    """状态变更记录"""
    from_state: EventState
    to_state: EventState
    timestamp: str
    reason: str
    operator: str = "system"


@dataclass
class EventStateRecord:
    """事件状态记录"""
    event_id: str
    current_state: EventState
    history: List[StateTransition] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    updated_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class EventStateMachine:
    """
    事件状态机
    管理15种状态流转，确保状态变更合法且可追溯
    """

    def __init__(self):
        self._records: Dict[str, EventStateRecord] = {}
        self.logger = logging.getLogger(__name__)

    def init_event(self, event_id: str) -> EventStateRecord:
        """初始化事件状态"""
        record = EventStateRecord(
            event_id=event_id,
            current_state=EventState.PENDING
        )
        self._records[event_id] = record
        self.logger.info(f"[状态机] 初始化事件: {event_id}, 状态: PENDING")
        return record

    def get_state(self, event_id: str) -> Optional[EventState]:
        """获取事件当前状态"""
        record = self._records.get(event_id)
        return record.current_state if record else None

    def get_record(self, event_id: str) -> Optional[EventStateRecord]:
        """获取事件状态记录"""
        return self._records.get(event_id)

    def transition(
        self,
        event_id: str,
        to_state: EventState,
        reason: str,
        operator: str = "system"
    ) -> bool:
        """
        状态转换
        Args:
            event_id: 事件ID
            to_state: 目标状态
            reason: 转换原因
            operator: 操作者（system/user）
        Returns:
            是否转换成功
        """
        record = self._records.get(event_id)
        if not record:
            self.logger.error(f"[状态机] 事件不存在: {event_id}")
            return False

        from_state = record.current_state

        # 检查状态流转是否合法
        if to_state not in STATE_TRANSITIONS.get(from_state, []):
            self.logger.error(
                f"[状态机] 非法状态转换: {event_id}, "
                f"{from_state.value} -> {to_state.value}"
            )
            return False

        # 执行状态转换
        transition = StateTransition(
            from_state=from_state,
            to_state=to_state,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            reason=reason,
            operator=operator
        )

        record.history.append(transition)
        record.current_state = to_state
        record.updated_at = transition.timestamp

        self.logger.info(
            f"[状态机] 状态转换成功: {event_id}, "
            f"{from_state.value} -> {to_state.value}, 原因: {reason}"
        )
        return True

    def can_transition(self, event_id: str, to_state: EventState) -> bool:
        """检查是否可以转换到目标状态"""
        record = self._records.get(event_id)
        if not record:
            return False
        return to_state in STATE_TRANSITIONS.get(record.current_state, [])


# ============================================================================
# 父智能体编排器
# ============================================================================

class SecurityEventOrchestrator(Agent):
    """
    安全事件协调父智能体
    协调调度四大专家智能体处理安全事件，实现全流程自动化闭环
    """
    name: str = "security_orchestrator"
    display_name: str = "安全事件协调器"
    description: str = "协调调度四大专家智能体处理安全事件，实现全流程自动化闭环"

    instruction: str = """
你是XSOC安全运营系统的核心调度智能体，负责协调四个专家智能体完成安全事件的全流程处理：
1. 事件研判专家(InvestigationAgent) - 研判事件真实性，区分误报和真实攻击
2. 溯源分析专家(TracingAgent) - 还原攻击路径，提取攻击线索
3. 风险处置专家(ResponseAgent) - 制定处置策略，执行处置操作
4. 数据可视化专家(VisualizationAgent) - 生成报告，完成归档

你的职责：
- 接收安全事件，启动处理流程
- 按顺序调度各专家智能体
- 处理分支逻辑（误报、真实事件、可疑待确认）
- 处理异常情况和人工干预
- 确保全流程闭环，所有事件最终归档
"""

    def __init__(self, **kwargs):
        # 注册子智能体
        kwargs["sub_agents"] = [
            InvestigationAgent(),
            TracingAgent(),
            ResponseAgent(),
            VisualizationAgent()
        ]
        super().__init__(**kwargs)

        # 初始化状态机
        self.state_machine = EventStateMachine()

        # 重试配置
        self.retry_config = {
            "max_retries": 3,
            "base_delay": 1.0,  # 秒
            "max_delay": 8.0,
        }

        # 重试计数器
        self.retry_count: Dict[str, int] = {}

        # 待人工审核队列
        self.pending_approval: Dict[str, Dict[str, Any]] = {}

        self.logger = logging.getLogger(__name__)

    async def run(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        智能体执行入口 - 主流程控制
        """
        trace_id = str(uuid.uuid4())

        # 提取事件ID
        event_id = self._extract_event_id(event_data)
        if not event_id:
            return {"status": "failed", "error": "无法提取事件ID"}

        # 初始化状态机
        self.state_machine.init_event(event_id)

        try:
            # ========== Step 0: 格式校验 ==========
            self.state_machine.transition(
                event_id, EventState.VALIDATING, "开始格式校验"
            )
            validated_data = await self._validate_event(event_data)
            if not validated_data:
                self.state_machine.transition(
                    event_id, EventState.FAILED, "格式校验失败"
                )
                return {"status": "failed", "event_id": event_id, "error": "事件格式校验失败"}

            # ========== Step 1: 事件研判 ==========
            self.state_machine.transition(
                event_id, EventState.INVESTIGATING, "开始研判"
            )
            investigate_result = await self._execute_with_retry(
                "investigation_agent", validated_data, event_id, trace_id
            )

            # 研判结果分支处理
            if investigate_result.get("result") == "误报":
                return await self._handle_false_positive(
                    event_id, investigate_result, trace_id
                )
            elif investigate_result.get("result") == "可疑待确认":
                return await self._handle_need_human(
                    event_id, investigate_result, "investigation", trace_id
                )

            # ========== Step 2: 溯源分析 ==========
            self.state_machine.transition(
                event_id, EventState.TRACING, "研判完成，开始溯源"
            )
            tracing_result = await self._execute_with_retry(
                "tracing_agent", investigate_result, event_id, trace_id
            )

            # 循环溯源逻辑：发现新线索回退研判
            if tracing_result.get("need_reinvestigation"):
                self.logger.info(f"[Flow] 溯源发现新线索，回退研判阶段: {event_id}")
                self.state_machine.transition(
                    event_id, EventState.INVESTIGATING, "溯源发现新线索，重新研判"
                )
                # 合并新证据重新研判
                new_event_data = {**validated_data, "new_evidence": tracing_result.get("new_evidence")}
                return await self.run(new_event_data)

            # 溯源结果存疑
            if tracing_result.get("need_human_confirm"):
                return await self._handle_need_human(
                    event_id, tracing_result, "tracing", trace_id
                )

            # ========== Step 3: 风险处置 ==========
            self.state_machine.transition(
                event_id, EventState.PROCESSING, "溯源完成，开始处置"
            )

            # 处置校验
            self.state_machine.transition(
                event_id, EventState.VALIDATING_DISPOSAL, "处置策略生成完成，进行安全校验"
            )

            # 高风险操作需要人工审核
            if self._is_high_risk(tracing_result):
                return await self._handle_need_human(
                    event_id, tracing_result, "response", trace_id
                )

            # 执行处置
            self.state_machine.transition(
                event_id, EventState.EXECUTING_DISPOSAL, "安全校验通过，开始执行处置"
            )
            response_result = await self._execute_with_retry(
                "response_agent", tracing_result, event_id, trace_id
            )

            # 处置验证
            self.state_machine.transition(
                event_id, EventState.VERIFYING_DISPOSAL, "处置执行完成，验证效果"
            )

            # 处置失败处理
            if response_result.get("result") == "处置失败":
                self.state_machine.transition(
                    event_id, EventState.FAILED, "处置验证失败"
                )
                # 处置失败转人工审核
                return await self._handle_need_human(
                    event_id, response_result, "response_failed", trace_id
                )

            # ========== Step 4: 数据可视化与归档 ==========
            return await self._handle_archive(event_id, response_result, trace_id)

        except Exception as e:
            self.logger.error(f"[Flow] 流程异常: {event_id}, 错误: {str(e)}")
            self.state_machine.transition(
                event_id, EventState.FAILED, f"流程异常: {str(e)}"
            )
            return {"status": "failed", "event_id": event_id, "error": str(e)}

    async def _validate_event(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """事件格式校验"""
        try:
            # 使用 SecurityEvent 进行格式校验
            security_event = SecurityEvent.from_input(event_data)
            return security_event.model_dump()
        except Exception as e:
            self.logger.error(f"[Flow] 事件格式校验失败: {str(e)}")
            return None

    async def _execute_with_retry(
        self,
        agent_name: str,
        data: Dict[str, Any],
        event_id: str,
        trace_id: str
    ) -> Dict[str, Any]:
        """
        带重试机制的智能体执行
        指数退避重试：1s, 2s, 4s, 8s，最多3次
        """
        max_retries = self.retry_config["max_retries"]
        base_delay = self.retry_config["base_delay"]

        retry_key = f"{event_id}:{agent_name}"
        self.retry_count[retry_key] = 0

        for attempt in range(max_retries + 1):
            try:
                self.logger.info(
                    f"[Flow] 执行智能体: {agent_name}, "
                    f"事件: {event_id}, 尝试: {attempt + 1}/{max_retries + 1}"
                )

                result = await self.call_agent(agent_name, data)

                # 成功则清除重试计数
                self.retry_count.pop(retry_key, None)
                return result

            except Exception as e:
                self.retry_count[retry_key] = attempt + 1

                if attempt < max_retries:
                    # 计算退避时间
                    delay = min(base_delay * (2 ** attempt), self.retry_config["max_delay"])
                    self.logger.warning(
                        f"[Flow] 智能体执行失败，{delay}秒后重试: "
                        f"{agent_name}, 错误: {str(e)}"
                    )
                    await asyncio.sleep(delay)
                else:
                    self.logger.error(
                        f"[Flow] 智能体执行失败，已达最大重试次数: "
                        f"{agent_name}, 错误: {str(e)}"
                    )
                    raise

        # 不应该到达这里
        raise RuntimeError(f"智能体执行失败: {agent_name}")

    async def call_agent(self, agent_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """调用子智能体"""
        # 通过 VEADK 的 send_to_agent 或直接调用子智能体
        # 这里使用 VEADK 提供的子智能体调用方式
        sub_agent = None
        for agent in self.sub_agents:
            if agent.name == agent_name:
                sub_agent = agent
                break

        if not sub_agent:
            raise ValueError(f"未找到子智能体: {agent_name}")

        return await sub_agent.run(data)

    def _is_high_risk(self, result: Dict[str, Any]) -> bool:
        """判断是否为高风险操作"""
        risk_assessment = result.get("risk_assessment", {})
        risk_level = risk_assessment.get("risk_level", "low")

        # 高风险和严重级别的操作需要人工审核
        return risk_level in ["high", "critical"]

    async def _handle_false_positive(
        self,
        event_id: str,
        result: Dict[str, Any],
        trace_id: str
    ) -> Dict[str, Any]:
        """处理误报"""
        self.state_machine.transition(
            event_id, EventState.FALSE_POSITIVE, "判定为误报"
        )
        return await self._handle_archive(event_id, result, trace_id)

    async def _handle_need_human(
        self,
        event_id: str,
        result: Dict[str, Any],
        stage: str,
        trace_id: str
    ) -> Dict[str, Any]:
        """处理需要人工干预的情况"""
        self.state_machine.transition(
            event_id, EventState.PENDING_APPROVAL, f"{stage}阶段需要人工审核"
        )

        # 记录待审核信息
        self.pending_approval[event_id] = {
            "stage": stage,
            "result": result,
            "trace_id": trace_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self.logger.info(f"[Flow] 事件等待人工审核: {event_id}, 阶段: {stage}")

        return {
            "status": "pending_approval",
            "event_id": event_id,
            "stage": stage,
            "message": "等待人工审核",
            "current_state": self.state_machine.get_state(event_id).value,
            "data": result
        }

    async def _handle_archive(
        self,
        event_id: str,
        result: Dict[str, Any],
        trace_id: str
    ) -> Dict[str, Any]:
        """处理归档"""
        self.state_machine.transition(
            event_id, EventState.VISUALIZING, "开始生成报告"
        )

        # 调用可视化智能体
        archive_result = await self._execute_with_retry(
            "visualization_agent", result, event_id, trace_id
        )

        self.state_machine.transition(
            event_id, EventState.ARCHIVING, "开始归档"
        )

        # 归档完成
        self.state_machine.transition(
            event_id, EventState.COMPLETED, "全流程处理完成"
        )

        return {
            "status": "completed",
            "event_id": event_id,
            "trace_id": trace_id,
            "final_state": self.state_machine.get_state(event_id).value,
            "result": archive_result
        }

    def _extract_event_id(self, event_data: Dict[str, Any]) -> Optional[str]:
        """从事件数据中提取事件ID"""
        return (
            event_data.get("event_id") or
            event_data.get("uuId") or
            event_data.get("alert_id") or
            str(uuid.uuid4())
        )

    # ========================================================================
    # 人工干预接口
    # ========================================================================

    async def approve(
        self,
        event_id: str,
        approver: str = "user",
        comment: str = ""
    ) -> Dict[str, Any]:
        """
        人工审核通过，继续流程
        """
        pending = self.pending_approval.get(event_id)
        if not pending:
            return {"status": "failed", "error": "未找到待审核事件"}

        stage = pending["stage"]
        result = pending["result"]
        trace_id = pending["trace_id"]

        self.logger.info(f"[Flow] 人工审核通过: {event_id}, 审批人: {approver}")

        # 清除待审核状态
        del self.pending_approval[event_id]

        # 根据阶段继续流程
        if stage == "investigation":
            # 可疑事件确认后继续溯源
            self.state_machine.transition(
                event_id, EventState.TRACING, f"人工审核通过({approver}): {comment}"
            )
            return await self.run(result)

        elif stage == "tracing":
            # 溯源存疑确认后继续处置
            self.state_machine.transition(
                event_id, EventState.PROCESSING, f"人工审核通过({approver}): {comment}"
            )
            return await self.run(result)

        elif stage == "response":
            # 高风险操作审批通过后执行
            self.state_machine.transition(
                event_id, EventState.EXECUTING_DISPOSAL, f"人工审核通过({approver}): {comment}"
            )
            response_result = await self._execute_with_retry(
                "response_agent", result, event_id, trace_id
            )
            return await self._handle_archive(event_id, response_result, trace_id)

        elif stage == "response_failed":
            # 处置失败后人工确认，继续归档
            return await self._handle_archive(event_id, result, trace_id)

        return {"status": "failed", "error": f"未知审核阶段: {stage}"}

    async def reject(
        self,
        event_id: str,
        approver: str = "user",
        comment: str = ""
    ) -> Dict[str, Any]:
        """
        人工审核拒绝，进入归档
        """
        pending = self.pending_approval.get(event_id)
        if not pending:
            return {"status": "failed", "error": "未找到待审核事件"}

        result = pending["result"]
        trace_id = pending["trace_id"]

        self.logger.info(f"[Flow] 人工审核拒绝: {event_id}, 审批人: {approver}")

        # 清除待审核状态
        del self.pending_approval[event_id]

        # 拒绝后直接归档
        return await self._handle_archive(event_id, result, trace_id)

    async def close(
        self,
        event_id: str,
        closer: str = "user",
        reason: str = ""
    ) -> Dict[str, Any]:
        """
        人工关闭事件
        """
        pending = self.pending_approval.get(event_id)
        result = pending.get("result", {}) if pending else {}
        trace_id = pending.get("trace_id", str(uuid.uuid4())) if pending else str(uuid.uuid4())

        self.logger.info(f"[Flow] 人工关闭事件: {event_id}, 操作人: {closer}")

        # 清除待审核状态
        if event_id in self.pending_approval:
            del self.pending_approval[event_id]

        # 关闭后仍需归档
        self.state_machine.transition(
            event_id, EventState.CLOSED, f"人工关闭({closer}): {reason}"
        )

        return await self._handle_archive(event_id, result, trace_id)

    async def modify_and_continue(
        self,
        event_id: str,
        modified_data: Dict[str, Any],
        modifier: str = "user",
        comment: str = ""
    ) -> Dict[str, Any]:
        """
        修改结果后继续流程
        """
        pending = self.pending_approval.get(event_id)
        if not pending:
            return {"status": "failed", "error": "未找到待审核事件"}

        self.logger.info(f"[Flow] 人工修改结果: {event_id}, 操作人: {modifier}")

        # 清除待审核状态
        del self.pending_approval[event_id]

        # 使用修改后的数据继续流程
        return await self.run(modified_data)

    def get_pending_events(self) -> Dict[str, Dict[str, Any]]:
        """获取所有待审核事件"""
        return self.pending_approval.copy()

    def get_event_status(self, event_id: str) -> Optional[Dict[str, Any]]:
        """获取事件状态"""
        record = self.state_machine.get_record(event_id)
        if not record:
            return None

        return {
            "event_id": event_id,
            "current_state": record.current_state.value,
            "current_state_name": record.current_state.display_name,
            "history": [
                {
                    "from_state": t.from_state.value,
                    "to_state": t.to_state.value,
                    "timestamp": t.timestamp,
                    "reason": t.reason,
                    "operator": t.operator
                }
                for t in record.history
            ],
            "created_at": record.created_at,
            "updated_at": record.updated_at
        }


# ============================================================================
# 根智能体实例（供 main.py 使用）
# ============================================================================

root_agent = SecurityEventOrchestrator()

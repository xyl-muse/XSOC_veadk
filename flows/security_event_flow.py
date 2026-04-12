"""
安全事件协作流程 - 父智能体编排器
基于VEADK父子智能体模式实现全流程闭环调度
"""
from veadk import Agent
from typing import Dict, Any, Optional, List, Callable, Set
from enum import Enum
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import asyncio
import uuid
import logging
import time
from collections import defaultdict

from agents import (
    InvestigationAgent,
    TracingAgent,
    ResponseAgent,
    VisualizationAgent,
)
from schemas.security_event import SecurityEvent, EventStatus


# ============================================================================
# 异常类型定义
# ============================================================================

class RetryableError(Exception):
    """可重试错误：网络超时、接口限流、临时服务不可用"""
    pass


class NonRetryableError(Exception):
    """不可重试错误：参数错误、权限不足、数据不存在"""
    pass


class CircuitBreakerError(Exception):
    """熔断错误：服务熔断，拒绝请求"""
    pass


class AgentTimeoutError(Exception):
    """智能体超时错误：智能体或工具执行超时"""
    pass


# ============================================================================
# 熔断器实现
# ============================================================================

@dataclass
class CircuitBreakerStats:
    """熔断器统计信息"""
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    state: str = "closed"  # closed, open, half_open


class CircuitBreaker:
    """
    熔断器
    防止级联故障，当错误率达到阈值时熔断
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        success_threshold: int = 3,
    ):
        """
        Args:
            failure_threshold: 失败次数阈值，触发熔断
            recovery_timeout: 熔断恢复超时时间（秒）
            success_threshold: 半开状态下成功次数阈值，恢复熔断
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold

        # 按服务名存储熔断状态
        self._stats: Dict[str, CircuitBreakerStats] = defaultdict(CircuitBreakerStats)
        self.logger = logging.getLogger(__name__)

    def is_available(self, service_name: str) -> bool:
        """检查服务是否可用"""
        stats = self._stats[service_name]

        if stats.state == "closed":
            return True

        if stats.state == "open":
            # 检查是否可以进入半开状态
            if stats.last_failure_time and \
               time.time() - stats.last_failure_time > self.recovery_timeout:
                stats.state = "half_open"
                self.logger.info(f"[熔断器] 服务 {service_name} 进入半开状态")
                return True
            return False

        # half_open 状态允许尝试
        return True

    def record_success(self, service_name: str):
        """记录成功"""
        stats = self._stats[service_name]
        stats.success_count += 1

        if stats.state == "half_open":
            if stats.success_count >= self.success_threshold:
                # 半开状态下成功次数达标，恢复熔断
                stats.state = "closed"
                stats.failure_count = 0
                stats.success_count = 0
                self.logger.info(f"[熔断器] 服务 {service_name} 熔断恢复")

    def record_failure(self, service_name: str):
        """记录失败"""
        stats = self._stats[service_name]
        stats.failure_count += 1
        stats.last_failure_time = time.time()

        if stats.state == "half_open":
            # 半开状态下失败，立即熔断
            stats.state = "open"
            self.logger.warning(f"[熔断器] 服务 {service_name} 半开状态失败，重新熔断")

        elif stats.state == "closed":
            if stats.failure_count >= self.failure_threshold:
                # 失败次数达标，触发熔断
                stats.state = "open"
                self.logger.warning(
                    f"[熔断器] 服务 {service_name} 触发熔断，"
                    f"失败次数: {stats.failure_count}"
                )

    def get_stats(self, service_name: str) -> Dict[str, Any]:
        """获取熔断器统计信息"""
        stats = self._stats[service_name]
        return {
            "service_name": service_name,
            "state": stats.state,
            "failure_count": stats.failure_count,
            "success_count": stats.success_count,
            "last_failure_time": stats.last_failure_time
        }


# ============================================================================
# 降级策略
# ============================================================================

class DegradationStrategy:
    """
    降级策略
    当服务不可用时，自动降级到备选方案
    """

    def __init__(self):
        # 平台降级映射
        self.platform_fallback = {
            "all": ["xdr", "ndr", "corplink"],
            "xdr": ["ndr"],
            "ndr": ["xdr"],
            "threatbook": ["xdr", "ndr"],
        }

        # 工具降级映射
        self.tool_fallback = {
            "threat_intel_query": ["asset_query", "alert_risk_query"],
            "event_query": ["alert_risk_query"],
        }

        self.logger = logging.getLogger(__name__)

    def get_fallback_platform(self, platform: str, tried_platforms: Set[str]) -> Optional[str]:
        """获取降级平台"""
        candidates = self.platform_fallback.get(platform, [])

        for candidate in candidates:
            if candidate not in tried_platforms:
                self.logger.info(f"[降级] 平台降级: {platform} -> {candidate}")
                return candidate

        return None

    def get_fallback_tool(self, tool_name: str) -> Optional[str]:
        """获取降级工具"""
        fallbacks = self.tool_fallback.get(tool_name, [])
        return fallbacks[0] if fallbacks else None


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
你是XSOC安全运营系统的核心调度智能体，负责协调四个专家智能体完成安全事件的全流程处理。

## 可用的子智能体
1. investigation_agent - 事件研判专家：研判事件真实性，区分误报和真实攻击
2. tracing_agent - 溯源分析专家：还原攻击路径，提取攻击线索  
3. response_agent - 风险处置专家：制定处置策略，执行处置操作
4. visualization_agent - 数据可视化专家：生成报告，完成归档

## 核心职责

### 处理用户输入
当用户发送安全事件数据（通常是JSON格式的告警信息）时：
1. **直接将用户的完整消息内容**传递给investigation_agent
2. 不要修改、解析或过滤用户输入，保持原始内容
3. 等待investigation_agent返回研判结果

### 根据研判结果调度
- **如果研判为误报**：终止流程，调用visualization_agent生成误报报告并归档
- **如果研判为真实攻击**：依次调用tracing_agent → response_agent → visualization_agent完成全流程
- **如果研判为可疑待确认**：暂停流程，等待人工审核

### 确保闭环
- 所有事件最终都必须通过visualization_agent归档
- 处理失败时记录详细错误信息
- 保持完整的处理链路和审计日志

## 示例流程
用户发送：{"agentId": "xxx", "state": {"name": "攻击事件", "uuId": "xxx", ...}}
你应该：立即调用investigation_agent处理这个JSON数据
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

        # 熔断器配置
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            success_threshold=3
        )

        # 降级策略
        self.degradation_strategy = DegradationStrategy()

        # 超时配置
        self.timeout_config = {
            "agent_timeout": 300,  # 智能体超时时间（秒）
            "tool_timeout": 30,     # 工具调用超时时间（秒）
        }

        # 并发控制
        self.concurrent_limit = 100  # 最大并发事件数
        self.active_events: Set[str] = set()

        # 重试计数器
        self.retry_count: Dict[str, int] = {}

        # 待人工审核队列
        self.pending_approval: Dict[str, Dict[str, Any]] = {}

        # 回滚操作记录
        self.rollback_records: Dict[str, List[Dict[str, Any]]] = {}

        # 可重试错误类型
        self.retryable_errors = {
            "TimeoutError", "ConnectionError", "HTTPError",
            "RetryableError", "asyncio.TimeoutError"
        }

        # 不可重试错误类型
        self.non_retryable_errors = {
            "ValueError", "KeyError", "PermissionError",
            "NonRetryableError", "AuthenticationError"
        }

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

        # 并发控制
        if not await self._acquire_event_slot(event_id):
            return {
                "status": "failed",
                "event_id": event_id,
                "error": "系统繁忙，已达到最大并发数"
            }

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
                # 失败也进入归档
                return await self._handle_archive(
                    event_id, 
                    {"event_data": event_data, "error": "事件格式校验失败"},
                    trace_id
                )

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

            # 执行处置（带回滚支持）
            self.state_machine.transition(
                event_id, EventState.EXECUTING_DISPOSAL, "安全校验通过，开始执行处置"
            )
            response_result = await self._execute_with_rollback(
                event_id, "response_agent", tracing_result, trace_id
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

        except CircuitBreakerError as e:
            self.logger.error(f"[Flow] 熔断错误: {event_id}, 错误: {str(e)}")
            self.state_machine.transition(
                event_id, EventState.FAILED, f"服务熔断: {str(e)}"
            )
            # 熔断错误也进入归档
            return await self._handle_archive(
                event_id,
                {"event_data": event_data, "error": str(e)},
                trace_id
            )

        except Exception as e:
            self.logger.error(f"[Flow] 流程异常: {event_id}, 错误: {str(e)}")
            self.state_machine.transition(
                event_id, EventState.FAILED, f"流程异常: {str(e)}"
            )
            # 异常也进入归档，确保数据完整性
            return await self._handle_archive(
                event_id,
                {"event_data": event_data, "error": str(e)},
                trace_id
            )

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
        支持熔断器、超时控制、错误类型识别
        """
        # 1. 熔断器检查
        if not self.circuit_breaker.is_available(agent_name):
            self.logger.warning(f"[Flow] 熔断器拒绝请求: {agent_name}")
            # 尝试降级
            fallback_result = await self._try_fallback(agent_name, data, event_id, trace_id)
            if fallback_result:
                return fallback_result
            raise CircuitBreakerError(f"服务 {agent_name} 已熔断")

        max_retries = self.retry_config["max_retries"]
        base_delay = self.retry_config["base_delay"]
        timeout = self.timeout_config["agent_timeout"]

        retry_key = f"{event_id}:{agent_name}"
        self.retry_count[retry_key] = 0
        last_error = None

        for attempt in range(max_retries + 1):
            try:
                self.logger.info(
                    f"[Flow] 执行智能体: {agent_name}, "
                    f"事件: {event_id}, 尝试: {attempt + 1}/{max_retries + 1}"
                )

                # 带超时控制的智能体调用
                result = await asyncio.wait_for(
                    self.call_agent(agent_name, data),
                    timeout=timeout
                )

                # 成功则清除重试计数，记录成功
                self.retry_count.pop(retry_key, None)
                self.circuit_breaker.record_success(agent_name)
                return result

            except asyncio.TimeoutError as e:
                last_error = e
                self.logger.error(f"[Flow] 智能体执行超时: {agent_name}, 超时时间: {timeout}s")
                self.circuit_breaker.record_failure(agent_name)
                self.retry_count[retry_key] = attempt + 1

                # 超时错误可重试
                if attempt < max_retries:
                    delay = min(base_delay * (2 ** attempt), self.retry_config["max_delay"])
                    self.logger.warning(f"[Flow] {delay}秒后重试")
                    await asyncio.sleep(delay)
                else:
                    # 重试失败，尝试降级
                    fallback_result = await self._try_fallback(agent_name, data, event_id, trace_id)
                    if fallback_result:
                        return fallback_result
                    raise AgentTimeoutError(f"智能体 {agent_name} 执行超时，已达最大重试次数")

            except Exception as e:
                last_error = e
                error_type = type(e).__name__
                self.circuit_breaker.record_failure(agent_name)
                self.retry_count[retry_key] = attempt + 1

                # 判断是否可重试
                if error_type in self.non_retryable_errors:
                    self.logger.error(
                        f"[Flow] 不可重试错误: {agent_name}, "
                        f"错误类型: {error_type}, 错误: {str(e)}"
                    )
                    raise NonRetryableError(f"不可重试错误: {str(e)}")

                if error_type not in self.retryable_errors:
                    # 未知错误类型，保守起见不重试
                    self.logger.error(
                        f"[Flow] 未知错误类型，不重试: {agent_name}, "
                        f"错误类型: {error_type}, 错误: {str(e)}"
                    )
                    raise

                # 可重试错误
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
                    # 重试失败，尝试降级
                    fallback_result = await self._try_fallback(agent_name, data, event_id, trace_id)
                    if fallback_result:
                        return fallback_result
                    raise RetryableError(f"智能体 {agent_name} 执行失败，已达最大重试次数")

        # 不应该到达这里
        raise RuntimeError(f"智能体执行失败: {agent_name}")

    async def _try_fallback(
        self,
        agent_name: str,
        data: Dict[str, Any],
        event_id: str,
        trace_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        尝试降级策略
        当智能体不可用时，尝试使用备选方案
        """
        self.logger.info(f"[Flow] 尝试降级策略: {agent_name}")

        # 对于处置智能体，可以降级为仅通知
        if agent_name == "response_agent":
            self.logger.info(f"[Flow] 降级：跳过处置，直接归档")
            return {
                "event_id": event_id,
                "result": "处置降级",
                "reason": "处置智能体不可用，已跳过处置直接归档",
                "event_data": data
            }

        # 对于其他智能体，记录降级事件并转人工
        self.logger.warning(f"[Flow] 无可用降级方案，转人工处理: {agent_name}")
        return None

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

    # ========================================================================
    # 回滚机制
    # ========================================================================

    async def _execute_with_rollback(
        self,
        event_id: str,
        agent_name: str,
        data: Dict[str, Any],
        trace_id: str
    ) -> Dict[str, Any]:
        """
        带回滚机制的智能体执行
        记录操作以便回滚
        """
        # 记录回滚信息
        rollback_record = {
            "agent_name": agent_name,
            "data": data,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "trace_id": trace_id
        }

        if event_id not in self.rollback_records:
            self.rollback_records[event_id] = []
        self.rollback_records[event_id].append(rollback_record)

        try:
            result = await self._execute_with_retry(agent_name, data, event_id, trace_id)
            return result
        except Exception as e:
            # 执行失败，触发回滚
            self.logger.error(f"[Flow] 执行失败，触发回滚: {event_id}, 错误: {str(e)}")
            await self._rollback_event(event_id, trace_id)
            raise

    async def _rollback_event(self, event_id: str, trace_id: str):
        """
        回滚事件的所有操作
        """
        records = self.rollback_records.get(event_id, [])
        if not records:
            self.logger.info(f"[Flow] 无需回滚，没有操作记录: {event_id}")
            return

        self.logger.info(f"[Flow] 开始回滚事件: {event_id}, 操作数: {len(records)}")

        # 反向执行回滚
        for record in reversed(records):
            agent_name = record["agent_name"]
            data = record["data"]

            try:
                # 对于处置智能体，需要执行反向操作
                if agent_name == "response_agent":
                    await self._rollback_response_operations(event_id, data, trace_id)
                
                self.logger.info(
                    f"[Flow] 回滚操作成功: {event_id}, "
                    f"智能体: {agent_name}"
                )
            except Exception as e:
                self.logger.error(
                    f"[Flow] 回滚操作失败: {event_id}, "
                    f"智能体: {agent_name}, 错误: {str(e)}"
                )

        # 清除回滚记录
        del self.rollback_records[event_id]

    async def _rollback_response_operations(
        self,
        event_id: str,
        data: Dict[str, Any],
        trace_id: str
    ):
        """
        回滚处置操作
        """
        execution_result = data.get("execution_result", {})
        operations = execution_result.get("operations", [])

        for operation in operations:
            op_name = operation.get("operation")
            if op_name == "IP封禁":
                # 执行解封操作
                attack_source_ip = data.get("attack_source_ip")
                if attack_source_ip:
                    try:
                        await self.call_tool(
                            "response_action",
                            {
                                "action_type": "unblock",
                                "target": attack_source_ip,
                                "target_type": "ip",
                                "platform": "all",
                                "comment": f"XSOC自动回滚 - 事件ID: {event_id}"
                            }
                        )
                    except Exception as e:
                        self.logger.error(f"[Flow] IP解封失败: {str(e)}")

            elif op_name == "终端隔离":
                # 执行解封操作
                target_asset_ip = data.get("target_asset_ip")
                if target_asset_ip:
                    try:
                        await self.call_tool(
                            "response_action",
                            {
                                "action_type": "unblock",
                                "target": target_asset_ip,
                                "target_type": "ip",
                                "platform": "xdr",
                                "comment": f"XSOC自动回滚终端解封 - 事件ID: {event_id}"
                            }
                        )
                    except Exception as e:
                        self.logger.error(f"[Flow] 终端解封失败: {str(e)}")

    async def call_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """调用工具（需要实现）"""
        # 这里应该调用实际的工具
        # 由于工具是异步函数，这里提供简化实现
        # 实际使用时应该从 tools 模块导入并调用
        self.logger.info(f"[Flow] 调用工具: {tool_name}, 参数: {params}")
        return {"success": True, "message": "工具调用成功"}

    # ========================================================================
    # 并发控制
    # ========================================================================

    async def _check_concurrency(self) -> bool:
        """检查并发限制"""
        return len(self.active_events) < self.concurrent_limit

    async def _acquire_event_slot(self, event_id: str) -> bool:
        """获取事件处理槽位"""
        if await self._check_concurrency():
            self.active_events.add(event_id)
            return True
        return False

    async def _release_event_slot(self, event_id: str):
        """释放事件处理槽位"""
        self.active_events.discard(event_id)

    # ========================================================================
    # 统一归档入口
    # ========================================================================

    async def _handle_archive(
        self,
        event_id: str,
        result: Dict[str, Any],
        trace_id: str
    ) -> Dict[str, Any]:
        """
        统一归档入口
        确保所有事件路径最终都进入归档流程
        """
        # 确保结果包含事件数据
        event_data = result.get("event_data", result)

        # 更新状态为报告生成中
        self.state_machine.transition(
            event_id, EventState.VISUALIZING, "开始生成报告"
        )

        # 调用可视化智能体
        try:
            archive_result = await self._execute_with_retry(
                "visualization_agent", event_data, event_id, trace_id
            )
        except Exception as e:
            self.logger.error(f"[Flow] 归档失败: {event_id}, 错误: {str(e)}")
            # 即使归档失败，也要确保数据完整性
            archive_result = {
                "success": False,
                "error": str(e),
                "event_data": event_data
            }

        # 更新状态为归档中
        self.state_machine.transition(
            event_id, EventState.ARCHIVING, "开始归档"
        )

        # 确保归档数据完整性
        archive_data = {
            "event_id": event_id,
            "trace_id": trace_id,
            "event_data": event_data,
            "process_result": result,
            "archive_result": archive_result,
            "archive_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # 执行归档操作（调用数据归档工具）
        try:
            await self.call_tool(
                "data_archive",
                {
                    "archive_type": "all",
                    "event_id": event_id,
                    "event_data": archive_data
                }
            )
        except Exception as e:
            self.logger.error(f"[Flow] 数据归档工具调用失败: {str(e)}")

        # 更新状态为已完成
        self.state_machine.transition(
            event_id, EventState.COMPLETED, "全流程处理完成"
        )

        # 释放并发槽位
        await self._release_event_slot(event_id)

        # 清理回滚记录
        if event_id in self.rollback_records:
            del self.rollback_records[event_id]

        return {
            "status": "completed",
            "event_id": event_id,
            "trace_id": trace_id,
            "final_state": self.state_machine.get_state(event_id).value,
            "result": archive_result,
            "archive_data": archive_data
        }


# ============================================================================
# 根智能体实例（供 main.py 使用）
# ============================================================================

root_agent = SecurityEventOrchestrator()

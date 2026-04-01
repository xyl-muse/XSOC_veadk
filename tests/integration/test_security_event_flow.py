"""Phase 3 安全事件流程集成测试
测试SecurityEventOrchestrator的全流程处理、异常处理和人工干预
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import time

from flows.security_event_flow import (
    EventStateMachine,
    EventState,
    CircuitBreaker,
    CircuitBreakerError,
    RetryableError,
    NonRetryableError,
    AgentTimeoutError,
)


# ==================== 状态机测试 ====================

class TestEventStateMachine:
    """状态机测试"""

    def test_init_event(self):
        """测试事件初始化"""
        state_machine = EventStateMachine()
        record = state_machine.init_event("event-001")

        assert record.event_id == "event-001"
        assert record.current_state == EventState.PENDING
        assert len(record.history) == 0

    def test_valid_state_transition(self):
        """测试合法状态转换"""
        state_machine = EventStateMachine()
        state_machine.init_event("event-001")

        result = state_machine.transition("event-001", EventState.VALIDATING, "开始校验")
        assert result is True
        assert state_machine.get_state("event-001") == EventState.VALIDATING

        result = state_machine.transition("event-001", EventState.INVESTIGATING, "开始研判")
        assert result is True
        assert state_machine.get_state("event-001") == EventState.INVESTIGATING

    def test_invalid_state_transition(self):
        """测试非法状态转换"""
        state_machine = EventStateMachine()
        state_machine.init_event("event-001")

        result = state_machine.transition("event-001", EventState.COMPLETED, "非法跳转")
        assert result is False
        assert state_machine.get_state("event-001") == EventState.PENDING

    def test_state_transition_history(self):
        """测试状态转换历史记录"""
        state_machine = EventStateMachine()
        state_machine.init_event("event-001")

        state_machine.transition("event-001", EventState.VALIDATING, "步骤1")
        state_machine.transition("event-001", EventState.INVESTIGATING, "步骤2")

        record = state_machine.get_record("event-001")
        assert len(record.history) == 2

    def test_can_transition(self):
        """测试状态转换检查"""
        state_machine = EventStateMachine()
        state_machine.init_event("event-001")

        assert state_machine.can_transition("event-001", EventState.VALIDATING) is True
        assert state_machine.can_transition("event-001", EventState.COMPLETED) is False

    def test_state_transition_to_pending_approval(self):
        """测试转换到待审核状态"""
        state_machine = EventStateMachine()
        state_machine.init_event("event-001")

        state_machine.transition("event-001", EventState.VALIDATING, "校验")
        state_machine.transition("event-001", EventState.INVESTIGATING, "研判")
        # 从 INVESTIGATING 可以转到 PENDING_APPROVAL
        result = state_machine.transition("event-001", EventState.PENDING_APPROVAL, "待审核")
        assert result is True

    def test_state_transition_to_failed(self):
        """测试转换到失败状态"""
        state_machine = EventStateMachine()
        state_machine.init_event("event-001")

        state_machine.transition("event-001", EventState.VALIDATING, "校验")
        # 从 VALIDATING 可以转到 FAILED
        result = state_machine.transition("event-001", EventState.FAILED, "校验失败")
        assert result is True


# ==================== 熔断器测试 ====================

class TestCircuitBreaker:
    """熔断器测试"""

    def test_circuit_breaker_closed_state(self):
        """测试熔断器关闭状态"""
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.is_available("test-service") is True

    def test_circuit_breaker_open_after_failures(self):
        """测试失败后熔断器打开"""
        cb = CircuitBreaker(failure_threshold=3)

        for _ in range(3):
            cb.record_failure("test-service")

        assert cb.is_available("test-service") is False

    def test_circuit_breaker_half_open_recovery(self):
        """测试熔断器半开状态恢复"""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=1, success_threshold=2)

        cb.record_failure("test-service")
        cb.record_failure("test-service")
        assert cb.is_available("test-service") is False

        time.sleep(1.1)
        assert cb.is_available("test-service") is True

        cb.record_success("test-service")
        cb.record_success("test-service")

        stats = cb.get_stats("test-service")
        assert stats["state"] == "closed"

    def test_circuit_breaker_record_success(self):
        """测试记录成功"""
        cb = CircuitBreaker()

        cb.record_success("test-service")
        stats = cb.get_stats("test-service")

        assert stats["success_count"] == 1
        assert stats["state"] == "closed"

    def test_circuit_breaker_half_open_failure(self):
        """测试半开状态失败重新熔断"""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=1)

        cb.record_failure("test-service")
        cb.record_failure("test-service")
        assert cb.is_available("test-service") is False

        time.sleep(1.1)
        assert cb.is_available("test-service") is True  # 进入半开

        cb.record_failure("test-service")  # 半开状态下失败
        assert cb.is_available("test-service") is False  # 重新熔断

    def test_circuit_breaker_multiple_services(self):
        """测试多服务熔断状态独立"""
        cb = CircuitBreaker(failure_threshold=2)

        cb.record_failure("service-a")
        cb.record_failure("service-a")
        cb.record_failure("service-b")

        assert cb.is_available("service-a") is False
        assert cb.is_available("service-b") is True


# ==================== Orchestrator基础测试 ====================

class TestOrchestratorBasics:
    """Orchestrator基础测试 - 不依赖Agent初始化的方法"""

    def test_extract_event_id_from_event_id(self):
        """测试从event_id字段提取ID"""
        from flows.security_event_flow import SecurityEventOrchestrator

        # 测试静态方法逻辑，通过创建一个临时实例
        # 由于 veadk.Agent 允许 extra 字段，我们可以创建一个测试实例
        orchestrator = SecurityEventOrchestrator()
        event_id = orchestrator._extract_event_id({"event_id": "test-001"})
        assert event_id == "test-001"

    def test_extract_event_id_from_uuId(self):
        """测试从uuId字段提取ID"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        event_id = orchestrator._extract_event_id({"uuId": "test-002"})
        assert event_id == "test-002"

    def test_extract_event_id_generate_new(self):
        """测试无ID时生成新ID"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        event_id = orchestrator._extract_event_id({})
        assert event_id is not None
        # 生成的ID是一个UUID格式
        assert len(event_id) == 36  # UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

    def test_is_high_risk_high_level(self):
        """测试高风险判断 - high级别"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        assert orchestrator._is_high_risk({"risk_assessment": {"risk_level": "high"}}) is True

    def test_is_high_risk_critical_level(self):
        """测试高风险判断 - critical级别"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        assert orchestrator._is_high_risk({"risk_assessment": {"risk_level": "critical"}}) is True

    def test_is_high_risk_low_level(self):
        """测试高风险判断 - low级别"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        assert orchestrator._is_high_risk({"risk_assessment": {"risk_level": "low"}}) is False

    def test_is_high_risk_no_assessment(self):
        """测试高风险判断 - 无评估"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        assert orchestrator._is_high_risk({}) is False

    def test_orchestrator_initialization(self):
        """测试Orchestrator初始化"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()

        assert orchestrator.name == "security_orchestrator"
        assert len(orchestrator.sub_agents) == 4
        assert orchestrator.retry_config["max_retries"] == 3
        assert orchestrator.concurrent_limit == 100

    def test_get_pending_events(self):
        """测试获取待审核事件列表"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        orchestrator.pending_approval = {
            "event-001": {"stage": "investigation"},
            "event-002": {"stage": "response"},
        }

        pending = orchestrator.get_pending_events()
        assert len(pending) == 2


# ==================== Orchestrator异步方法测试 ====================

class TestOrchestratorAsyncMethods:
    """Orchestrator异步方法测试"""

    @pytest.mark.asyncio
    async def test_acquire_release_event_slot(self):
        """测试并发控制 - 获取和释放槽位"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        orchestrator.concurrent_limit = 2
        orchestrator.active_events = set()

        # 获取槽位
        assert await orchestrator._acquire_event_slot("event-001") is True
        assert await orchestrator._acquire_event_slot("event-002") is True
        assert await orchestrator._acquire_event_slot("event-003") is False  # 超出限制

        # 释放槽位
        await orchestrator._release_event_slot("event-001")
        assert await orchestrator._acquire_event_slot("event-003") is True

    @pytest.mark.asyncio
    async def test_try_fallback_response_agent(self):
        """测试response_agent降级策略"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        result = await orchestrator._try_fallback(
            "response_agent", {"event_id": "test-001"}, "event-001", "trace-001"
        )

        assert result is not None
        assert result["result"] == "处置降级"

    @pytest.mark.asyncio
    async def test_try_fallback_visualization_agent(self):
        """测试visualization_agent降级策略 - 无可用降级方案"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        result = await orchestrator._try_fallback(
            "visualization_agent", {"event_id": "test-001"}, "event-001", "trace-001"
        )

        # visualization_agent 没有降级方案，返回 None
        assert result is None

    @pytest.mark.asyncio
    async def test_handle_need_human(self):
        """测试待人工确认处理"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        orchestrator.state_machine.init_event("event-001")

        result = await orchestrator._handle_need_human(
            "event-001", {"result": "可疑"}, "investigation", "trace-001"
        )

        assert result["status"] == "pending_approval"
        assert "event-001" in orchestrator.pending_approval


# ==================== 重试机制测试 ====================

class TestRetryMechanism:
    """重试机制测试"""

    @pytest.mark.asyncio
    async def test_retry_on_timeout(self):
        """测试超时重试机制"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        orchestrator.retry_config = {"max_retries": 3, "base_delay": 0.01, "max_delay": 0.1}
        orchestrator.timeout_config = {"agent_timeout": 0.01}
        orchestrator.state_machine.init_event("event-001")

        call_count = 0

        async def slow_agent(agent_name, data):
            nonlocal call_count
            call_count += 1
            raise asyncio.TimeoutError("Agent timeout")

        with patch.object(orchestrator, 'call_agent', side_effect=slow_agent):
            with pytest.raises((AgentTimeoutError, RetryableError, asyncio.TimeoutError)):
                await orchestrator._execute_with_retry("test_agent", {}, "event-001", "trace-001")

        # 应该重试3次 + 初始1次 = 4次
        assert call_count == 4

    @pytest.mark.asyncio
    async def test_no_retry_on_value_error(self):
        """测试ValueError不重试"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        orchestrator.retry_config = {"max_retries": 3, "base_delay": 0.01, "max_delay": 0.1}
        orchestrator.timeout_config = {"agent_timeout": 30}
        orchestrator.state_machine.init_event("event-001")

        call_count = 0

        async def failing_agent(agent_name, data):
            nonlocal call_count
            call_count += 1
            raise ValueError("参数错误")

        with patch.object(orchestrator, 'call_agent', side_effect=failing_agent):
            with pytest.raises((NonRetryableError, ValueError)):
                await orchestrator._execute_with_retry("test_agent", {}, "event-001", "trace-001")

        # 不应该重试
        assert call_count == 1


# ==================== 归档测试 ====================

class TestArchive:
    """归档测试"""

    @pytest.mark.asyncio
    async def test_archive_data_completeness(self):
        """测试归档数据完整性"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        orchestrator.state_machine.init_event("event-001")

        async def mock_visualization(agent_name, data):
            return {"result": "归档成功", "event_data": data}

        with patch.object(orchestrator, 'call_agent', side_effect=mock_visualization):
            result = await orchestrator._handle_archive(
                "event-001", {"event_data": {"event_id": "test-001"}}, "trace-001"
            )

        assert "archive_data" in result
        assert "event_id" in result["archive_data"]
        assert "archive_timestamp" in result["archive_data"]


# ==================== 全流程场景测试 ====================

class TestFullFlowScenarios:
    """全流程场景测试"""

    @pytest.mark.asyncio
    async def test_false_positive_flow(self):
        """测试误报处理全流程"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()

        # Mock _validate_event
        async def mock_validate(data):
            return data

        # Mock call_agent - 研判返回误报
        call_count = {"count": 0}

        async def mock_call_agent(agent_name, data):
            call_count["count"] += 1
            if agent_name == "investigation_agent":
                return {"result": "误报", "confidence": 0.95}
            elif agent_name == "visualization_agent":
                return {"result": "归档成功", "event_data": data}
            return {"result": "success"}

        with patch.object(orchestrator, '_validate_event', side_effect=mock_validate):
            with patch.object(orchestrator, 'call_agent', side_effect=mock_call_agent):
                result = await orchestrator.run({"event_id": "event-001", "alert_type": "test"})

        assert result["status"] == "completed"
        assert call_count["count"] >= 2  # 至少调用研判和归档

    @pytest.mark.asyncio
    async def test_real_attack_flow(self):
        """测试真实攻击处理全流程"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()

        async def mock_validate(data):
            return data

        call_sequence = []

        async def mock_call_agent(agent_name, data):
            call_sequence.append(agent_name)
            if agent_name == "investigation_agent":
                return {"result": "真实攻击", "attack_type": "lateral_movement"}
            elif agent_name == "tracing_agent":
                return {
                    "result": "溯源完成",
                    "attack_path": ["192.168.1.1 -> 192.168.1.2"],
                    "risk_assessment": {"risk_level": "medium"}  # 低风险，无需人工审核
                }
            elif agent_name == "response_agent":
                return {"result": "处置成功", "actions": ["block_ip"]}
            elif agent_name == "visualization_agent":
                return {"result": "归档成功", "event_data": data}
            return {"result": "success"}

        with patch.object(orchestrator, '_validate_event', side_effect=mock_validate):
            with patch.object(orchestrator, 'call_agent', side_effect=mock_call_agent):
                result = await orchestrator.run({"event_id": "event-001", "alert_type": "test"})

        assert result["status"] == "completed"
        # 验证调用顺序
        assert "investigation_agent" in call_sequence
        assert "tracing_agent" in call_sequence
        assert "response_agent" in call_sequence
        assert "visualization_agent" in call_sequence

    @pytest.mark.asyncio
    async def test_high_risk_approval_flow(self):
        """测试高风险操作人工审核流程"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()

        async def mock_validate(data):
            return data

        async def mock_call_agent(agent_name, data):
            if agent_name == "investigation_agent":
                return {"result": "真实攻击"}
            elif agent_name == "tracing_agent":
                return {
                    "result": "溯源完成",
                    "risk_assessment": {"risk_level": "critical"}  # 高风险
                }
            return {"result": "success"}

        with patch.object(orchestrator, '_validate_event', side_effect=mock_validate):
            with patch.object(orchestrator, 'call_agent', side_effect=mock_call_agent):
                result = await orchestrator.run({"event_id": "event-001", "alert_type": "test"})

        # 高风险操作应该等待人工审核
        assert result["status"] == "pending_approval"
        assert "event-001" in orchestrator.pending_approval


# ==================== 异常场景测试 ====================

class TestExceptionScenarios:
    """异常场景测试"""

    @pytest.mark.asyncio
    async def test_api_failure_with_retry(self):
        """测试API调用失败重试"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()
        orchestrator.retry_config = {"max_retries": 2, "base_delay": 0.01, "max_delay": 0.1}

        async def mock_validate(data):
            return data

        call_count = {"count": 0}

        async def failing_agent(agent_name, data):
            call_count["count"] += 1
            raise ConnectionError("API连接失败")

        with patch.object(orchestrator, '_validate_event', side_effect=mock_validate):
            with patch.object(orchestrator, 'call_agent', side_effect=failing_agent):
                result = await orchestrator.run({"event_id": "event-001"})

        # 流程会尝试重试，最终即使失败也会尝试归档
        # 归档成功则返回 completed，归档失败则返回 failed
        # 重点验证：1) 进行了重试 2) 结果包含错误信息
        assert call_count["count"] >= 2  # 至少重试一次
        assert result["status"] in ["completed", "failed", "pending_approval"]
        # 结果应该包含错误信息或归档数据
        assert "error" in result or "archive_data" in result

    @pytest.mark.asyncio
    async def test_circuit_breaker_trigger(self):
        """测试熔断触发"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()

        # 触发熔断
        orchestrator.circuit_breaker.record_failure("investigation_agent")
        orchestrator.circuit_breaker.record_failure("investigation_agent")
        orchestrator.circuit_breaker.record_failure("investigation_agent")
        orchestrator.circuit_breaker.record_failure("investigation_agent")
        orchestrator.circuit_breaker.record_failure("investigation_agent")

        assert orchestrator.circuit_breaker.is_available("investigation_agent") is False

    @pytest.mark.asyncio
    async def test_validation_failure(self):
        """测试格式校验失败"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()

        async def mock_validate_fail(data):
            return None  # 校验失败

        async def mock_archive(event_id, data, trace_id):
            return {"status": "completed", "archive_data": {"event_id": event_id}}

        with patch.object(orchestrator, '_validate_event', side_effect=mock_validate_fail):
            with patch.object(orchestrator, '_handle_archive', side_effect=mock_archive):
                result = await orchestrator.run({"event_id": "event-001"})

        # 校验失败应该触发归档
        assert result["status"] == "completed"


# ==================== 性能测试 ====================

class TestPerformance:
    """性能测试"""

    @pytest.mark.asyncio
    async def test_flow_overhead(self):
        """测试流程调度耗时"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()

        async def mock_validate(data):
            return data

        async def mock_call_agent(agent_name, data):
            return {"result": "误报"}

        start = time.time()

        with patch.object(orchestrator, '_validate_event', side_effect=mock_validate):
            with patch.object(orchestrator, 'call_agent', side_effect=mock_call_agent):
                await orchestrator.run({"event_id": "event-001"})

        elapsed = time.time() - start

        # 流程调度耗时应该 < 1秒（不含真实Agent调用）
        assert elapsed < 1.0, f"流程调度耗时 {elapsed:.3f}s 超过1秒阈值"

    @pytest.mark.asyncio
    async def test_concurrent_events(self):
        """测试并发事件处理"""
        from flows.security_event_flow import SecurityEventOrchestrator

        orchestrator = SecurityEventOrchestrator()

        async def mock_validate(data):
            return data

        async def mock_call_agent(agent_name, data):
            await asyncio.sleep(0.01)  # 模拟处理时间
            return {"result": "误报"}

        with patch.object(orchestrator, '_validate_event', side_effect=mock_validate):
            with patch.object(orchestrator, 'call_agent', side_effect=mock_call_agent):
                # 并发处理10个事件
                tasks = [
                    orchestrator.run({"event_id": f"event-{i}"})
                    for i in range(10)
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

        # 大部分应该成功
        successful = sum(1 for r in results if not isinstance(r, Exception) and r.get("status") == "completed")
        assert successful >= 8, f"并发成功率 {successful}/10 低于80%"
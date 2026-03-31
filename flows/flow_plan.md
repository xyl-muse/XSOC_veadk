# Phase 3: 智能体协作流程开发计划

> 本文档记录 Phase 3 的完整设计思路，供开发前讨论和确认。

---

## 一、整体目标

将四个独立的专家智能体（研判、溯源、处置、可视化）通过**协调智能体（Orchestrator）**串联起来，形成完整的安全事件自动化处理链路。

```
┌─────────────────────────────────────────────────────────────────┐
│                    SecurityEventOrchestrator                     │
│                        （协调智能体/"大脑"）                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│   │ Investigation │───→│   Tracing    │───→│   Response   │      │
│   │    Agent     │    │    Agent     │    │    Agent     │      │
│   │  (研判专家)   │    │  (溯源专家)   │    │  (处置专家)   │      │
│   └──────────────┘    └──────────────┘    └──────────────┘      │
│          │                                        │              │
│          │ 误报                                   │              │
│          ▼                                        ▼              │
│   ┌──────────────┐                         ┌──────────────┐      │
│   │Visualization │◄────────────────────────│Visualization │      │
│   │    Agent     │                         │    Agent     │      │
│   │ (可视化专家)  │                         │ (可视化专家)  │      │
│   └──────────────┘                         └──────────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 二、VEADK 多智能体协作机制

### 2.1 框架原生支持

根据 VEADK (Volcengine Agent Development Kit) 框架规范：

```python
from veadk import Agent

# 父智能体通过 sub_agents 参数注册子智能体
class ParentAgent(Agent):
    def __init__(self, **kwargs):
        child1 = ChildAgent1()
        child2 = ChildAgent2()
        
        # 关键：注册子智能体
        kwargs["sub_agents"] = [child1, child2]
        super().__init__(**kwargs)
    
    async def run(self, user_input):
        # 调用子智能体
        result = await self.send_to_agent("child_agent_1", {"data": user_input})
        return result
```

### 2.2 智能体间通信

- `send_to_agent(agent_name, data)` - 向子智能体发送消息并获取结果
- `call_tool(tool_name, params)` - 调用工具
- 子智能体名称默认为类名的小写下划线形式（如 `InvestigationAgent` → `investigation_agent`）

### 2.3 远程智能体调用（可选）

VEADK 支持通过 A2A 协议调用远程部署的智能体：

```python
from veadk.a2a.remote_ve_agent import RemoteVeAgent

remote_agent = RemoteVeAgent(
    name="cloud_agent",
    url="https://your-agent-endpoint",
    auth_token="your-token"
)

local_agent = Agent(
    name="local_agent",
    sub_agents=[remote_agent]
)
```

---

## 三、事件状态机设计

### 3.1 状态定义

```python
from enum import Enum

class EventState(str, Enum):
    """安全事件处理状态"""
    
    NEW = "new"                      # 新告警（初始状态）
    INVESTIGATING = "investigating"  # 研判中
    TRACING = "tracing"              # 溯源中
    RESPONDING = "responding"        # 处置中
    ARCHIVING = "archiving"          # 归档中
    COMPLETED = "completed"          # 已完成（终态）
    FAILED = "failed"                # 失败
    NEED_HUMAN = "need_human"        # 需人工确认
    CANCELLED = "cancelled"          # 已取消
```

### 3.2 状态转换图

```
                    ┌─────────┐
                    │   NEW   │
                    └────┬────┘
                         │ 开始处理
                         ▼
                ┌─────────────────┐
                │  INVESTIGATING  │
                └────────┬────────┘
                         │
           ┌─────────────┼─────────────┐
           │             │             │
           │ 真实攻击    │ 误报        │ 失败
           ▼             ▼             ▼
    ┌───────────┐  ┌───────────┐  ┌─────────┐
    │  TRACING  │  │ ARCHIVING │  │ FAILED  │
    └─────┬─────┘  └─────┬─────┘  └────┬────┘
          │              │             │ 重试
          │              │             ▼
          ▼              │      ┌─────────────────┐
    ┌─────────────┐      │      │  INVESTIGATING  │
    │ RESPONDING  │      │      └─────────────────┘
    └──────┬──────┘      │
           │             │
    ┌──────┼──────┐      │
    │      │      │      │
    │ 正常  │ 高风险│ 失败 │
    ▼      ▼      ▼      │
┌────────┐ ┌──────────┐ ┌─────────┐
│ARCHIVING│ │NEED_HUMAN│ │ FAILED  │
└───┬────┘ └────┬─────┘ └─────────┘
    │           │
    │           │ 人工确认后
    │           ▼
    │     ┌───────────┐
    │     │RESPONDING │
    │     └─────┬─────┘
    │           │
    └─────┬─────┘
          │
          ▼
    ┌───────────┐
    │ COMPLETED │
    └───────────┘
```

### 3.3 状态机实现

```python
class EventStateMachine:
    """事件状态机"""
    
    # 允许的状态转换
    TRANSITIONS = {
        EventState.NEW: [EventState.INVESTIGATING],
        EventState.INVESTIGATING: [
            EventState.TRACING,      # 真实攻击
            EventState.ARCHIVING,    # 误报，直接归档
            EventState.FAILED        # 研判失败
        ],
        EventState.TRACING: [
            EventState.RESPONDING,   # 溯源完成，进入处置
            EventState.FAILED        # 溯源失败
        ],
        EventState.RESPONDING: [
            EventState.ARCHIVING,    # 处置完成，归档
            EventState.NEED_HUMAN,   # 高风险操作需人工确认
            EventState.FAILED        # 处置失败
        ],
        EventState.NEED_HUMAN: [
            EventState.RESPONDING,   # 人工确认后继续处置
            EventState.COMPLETED,    # 人工确认后直接完成
            EventState.CANCELLED     # 人工取消
        ],
        EventState.ARCHIVING: [
            EventState.COMPLETED,    # 归档完成
            EventState.FAILED        # 归档失败
        ],
        EventState.FAILED: [
            EventState.INVESTIGATING  # 允许重新处理
        ],
        EventState.COMPLETED: [],     # 终态，无后续转换
        EventState.CANCELLED: [],     # 终态，无后续转换
    }
    
    def __init__(self):
        self.states: Dict[str, EventState] = {}
        self.history: Dict[str, List[Dict]] = {}  # 状态变更历史
    
    def get_state(self, event_id: str) -> EventState:
        """获取事件当前状态"""
        return self.states.get(event_id, EventState.NEW)
    
    def transition(
        self, 
        event_id: str, 
        new_state: EventState,
        reason: str = ""
    ) -> EventState:
        """
        状态转换
        
        Args:
            event_id: 事件ID
            new_state: 目标状态
            reason: 转换原因
        
        Returns:
            转换后的状态
        
        Raises:
            ValueError: 非法状态转换
        """
        current = self.get_state(event_id)
        
        if new_state not in self.TRANSITIONS.get(current, []):
            raise ValueError(
                f"非法状态转换: {current.value} -> {new_state.value}"
            )
        
        # 记录状态变更
        self.states[event_id] = new_state
        
        if event_id not in self.history:
            self.history[event_id] = []
        
        self.history[event_id].append({
            "from_state": current.value,
            "to_state": new_state.value,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })
        
        return new_state
    
    def get_history(self, event_id: str) -> List[Dict]:
        """获取事件状态变更历史"""
        return self.history.get(event_id, [])
```

---

## 四、协调智能体设计（核心）

### 4.1 类结构

```python
class SecurityEventOrchestrator(Agent):
    """安全事件协调智能体"""
    
    # 基本信息
    name: str = "security_orchestrator"
    display_name: str = "安全事件协调器"
    description: str = "协调调度研判、溯源、处置、可视化专家智能体处理安全事件"
    
    # 配置参数
    max_retries: int = 3                    # 最大重试次数
    circuit_breaker_threshold: int = 5      # 熔断阈值（连续失败N次）
    circuit_breaker_reset_time: int = 300   # 熔断恢复时间（秒）
    
    # 内部状态
    state_machine: EventStateMachine        # 状态机
    retry_count: Dict[str, int]             # 重试计数器
    circuit_breaker: Dict[str, int]         # 熔断计数器
    circuit_breaker_open: Dict[str, bool]   # 熔断状态
    processing_events: Set[str]             # 正在处理的事件（防并发）
```

### 4.2 主流程实现

```python
async def process_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    处理安全事件的主流程
    
    Args:
        event_data: 安全事件数据（XDR告警或人工录入）
    
    Returns:
        处理结果字典
    """
    # 提取事件ID
    event_id = self._extract_event_id(event_data)
    
    # 防止并发处理同一事件
    if event_id in self.processing_events:
        return {
            "status": "error",
            "error": f"事件 {event_id} 正在处理中，请勿重复提交"
        }
    
    self.processing_events.add(event_id)
    self.retry_count[event_id] = 0
    
    self.logger.info(f"开始处理安全事件: {event_id}")
    
    try:
        # ========== Step 1: 事件研判 ==========
        self.state_machine.transition(event_id, EventState.INVESTIGATING, "开始研判")
        
        investigation_result = await self._execute_with_retry(
            agent_name="investigation_agent",
            data=event_data,
            event_id=event_id
        )
        
        # 判断研判结果
        if investigation_result.get("result") == "误报":
            self.logger.info(f"事件 {event_id} 判定为误报")
            return await self._handle_false_positive(event_id, investigation_result)
        
        if investigation_result.get("result") == "可疑待确认":
            self.logger.info(f"事件 {event_id} 可疑，需人工确认")
            return await self._handle_suspicious(event_id, investigation_result)
        
        # ========== Step 2: 溯源分析 ==========
        self.state_machine.transition(event_id, EventState.TRACING, "研判完成，开始溯源")
        
        tracing_result = await self._execute_with_retry(
            agent_name="tracing_agent",
            data=investigation_result,
            event_id=event_id
        )
        
        # 检查溯源是否发现新线索需要回退研判
        if tracing_result.get("need_reinvestigation"):
            self.logger.info(f"溯源发现新线索，回退研判阶段: {event_id}")
            return await self._handle_reinvestigation(event_id, tracing_result)
        
        # ========== Step 3: 风险处置 ==========
        self.state_machine.transition(event_id, EventState.RESPONDING, "溯源完成，开始处置")
        
        # 检查是否需要人工确认（高风险操作）
        if self._is_high_risk_operation(tracing_result):
            self.state_machine.transition(
                event_id, EventState.NEED_HUMAN, 
                "高风险操作需人工确认"
            )
            return {
                "status": "need_human",
                "event_id": event_id,
                "stage": "responding",
                "data": tracing_result,
                "risk_level": tracing_result.get("security_check", {}).get("risk_level"),
                "warnings": tracing_result.get("security_check", {}).get("warnings", [])
            }
        
        response_result = await self._execute_with_retry(
            agent_name="response_agent",
            data=tracing_result,
            event_id=event_id
        )
        
        # ========== Step 4: 数据归档 ==========
        self.state_machine.transition(event_id, EventState.ARCHIVING, "处置完成，开始归档")
        
        archive_result = await self._execute_with_retry(
            agent_name="visualization_agent",
            data=response_result,
            event_id=event_id
        )
        
        # 完成
        self.state_machine.transition(event_id, EventState.COMPLETED, "处理完成")
        self.logger.info(f"事件 {event_id} 处理完成")
        
        return archive_result
        
    except Exception as e:
        self.state_machine.transition(event_id, EventState.FAILED, str(e))
        self.logger.error(f"事件 {event_id} 处理失败: {e}")
        return {
            "status": "failed",
            "event_id": event_id,
            "error": str(e),
            "current_state": self.state_machine.get_state(event_id).value,
            "history": self.state_machine.get_history(event_id)
        }
    
    finally:
        self.processing_events.discard(event_id)
```

### 4.3 分支处理函数

```python
async def _handle_false_positive(
    self, 
    event_id: str, 
    investigation_result: Dict[str, Any]
) -> Dict[str, Any]:
    """处理误报事件"""
    self.state_machine.transition(event_id, EventState.ARCHIVING, "误报，直接归档")
    
    archive_result = await self._execute_with_retry(
        agent_name="visualization_agent",
        data=investigation_result,
        event_id=event_id
    )
    
    self.state_machine.transition(event_id, EventState.COMPLETED, "误报归档完成")
    return archive_result


async def _handle_suspicious(
    self, 
    event_id: str, 
    investigation_result: Dict[str, Any]
) -> Dict[str, Any]:
    """处理可疑事件（需人工确认）"""
    self.state_machine.transition(event_id, EventState.NEED_HUMAN, "可疑事件需人工确认")
    
    return {
        "status": "need_human",
        "event_id": event_id,
        "stage": "investigation",
        "data": investigation_result,
        "message": "事件可疑，需人工确认是否为真实攻击"
    }


async def _handle_reinvestigation(
    self, 
    event_id: str, 
    tracing_result: Dict[str, Any]
) -> Dict[str, Any]:
    """处理需要重新研判的情况"""
    # 循环溯源逻辑：发现新线索回退到研判阶段
    new_evidence = tracing_result.get("new_evidence", {})
    
    self.state_machine.transition(event_id, EventState.INVESTIGATING, "发现新线索，重新研判")
    
    investigation_result = await self._execute_with_retry(
        agent_name="investigation_agent",
        data={**tracing_result, "new_evidence": new_evidence},
        event_id=event_id
    )
    
    # 重新进入流程...
    # （实际实现中需要限制循环次数，避免无限循环）


def _is_high_risk_operation(self, data: Dict[str, Any]) -> bool:
    """判断是否为高风险操作"""
    security_check = data.get("security_check", {})
    risk_level = security_check.get("risk_level", "low")
    return risk_level in ["high", "critical"]
```

### 4.4 重试与熔断机制

```python
async def _execute_with_retry(
    self,
    agent_name: str,
    data: Dict[str, Any],
    event_id: str
) -> Dict[str, Any]:
    """
    带重试和熔断的智能体执行
    
    Args:
        agent_name: 智能体名称
        data: 传入数据
        event_id: 事件ID
    
    Returns:
        智能体执行结果
    
    Raises:
        Exception: 重试耗尽或熔断触发
    """
    # 检查熔断状态
    if self.circuit_breaker_open.get(agent_name, False):
        raise Exception(
            f"熔断器已打开: {agent_name} 暂时不可用，请稍后重试"
        )
    
    last_error = None
    
    for attempt in range(self.max_retries):
        try:
            # 调用子智能体
            result = await self.send_to_agent(agent_name, data)
            
            # 执行成功，重置计数器
            self.retry_count[event_id] = 0
            self.circuit_breaker[agent_name] = 0
            
            return result
            
        except Exception as e:
            last_error = e
            
            # 更新计数器
            self.retry_count[event_id] = self.retry_count.get(event_id, 0) + 1
            self.circuit_breaker[agent_name] = self.circuit_breaker.get(agent_name, 0) + 1
            
            self.logger.warning(
                f"智能体 {agent_name} 执行失败，"
                f"事件 {event_id}，第 {attempt + 1}/{self.max_retries} 次重试: {e}"
            )
            
            # 检查是否触发熔断
            if self.circuit_breaker[agent_name] >= self.circuit_breaker_threshold:
                self.circuit_breaker_open[agent_name] = True
                self.logger.error(
                    f"熔断触发: {agent_name}，连续失败 {self.circuit_breaker[agent_name]} 次"
                )
                # 启动熔断恢复定时器
                asyncio.create_task(
                    self._reset_circuit_breaker(agent_name)
                )
                raise Exception(
                    f"熔断触发: {agent_name} 连续失败次数过多"
                )
            
            # 指数退避等待
            wait_time = 2 ** attempt  # 1s, 2s, 4s...
            await asyncio.sleep(wait_time)
    
    raise Exception(
        f"智能体 {agent_name} 执行失败，已重试 {self.max_retries} 次: {last_error}"
    )


async def _reset_circuit_breaker(self, agent_name: str):
    """熔断恢复"""
    await asyncio.sleep(self.circuit_breaker_reset_time)
    self.circuit_breaker[agent_name] = 0
    self.circuit_breaker_open[agent_name] = False
    self.logger.info(f"熔断器恢复: {agent_name}")
```

### 4.5 人工确认后续处理

```python
async def continue_after_human_confirm(
    self,
    event_id: str,
    event_data: Dict[str, Any],
    approved: bool = True,
    comment: str = ""
) -> Dict[str, Any]:
    """
    人工确认后继续处理
    
    Args:
        event_id: 事件ID
        event_data: 事件数据
        approved: 是否批准执行
        comment: 人工备注
    
    Returns:
        处理结果
    """
    current_state = self.state_machine.get_state(event_id)
    
    if current_state != EventState.NEED_HUMAN:
        return {
            "status": "error",
            "error": f"事件 {event_id} 当前状态为 {current_state.value}，无需人工确认"
        }
    
    if not approved:
        # 拒绝执行，标记为取消
        self.state_machine.transition(
            event_id, EventState.CANCELLED, 
            f"人工拒绝: {comment}"
        )
        return {
            "status": "cancelled",
            "event_id": event_id,
            "comment": comment
        }
    
    # 批准执行
    self.state_machine.transition(
        event_id, EventState.RESPONDING, 
        f"人工批准: {comment}"
    )
    
    try:
        response_result = await self._execute_with_retry(
            agent_name="response_agent",
            data={**event_data, "human_approved": True, "human_comment": comment},
            event_id=event_id
        )
        
        # 继续归档流程
        self.state_machine.transition(event_id, EventState.ARCHIVING, "处置完成")
        
        archive_result = await self._execute_with_retry(
            agent_name="visualization_agent",
            data=response_result,
            event_id=event_id
        )
        
        self.state_machine.transition(event_id, EventState.COMPLETED, "处理完成")
        return archive_result
        
    except Exception as e:
        self.state_machine.transition(event_id, EventState.FAILED, str(e))
        return {
            "status": "failed",
            "event_id": event_id,
            "error": str(e)
        }
```

---

## 五、与现有智能体的对接

### 5.1 现有智能体分析

查看现有智能体代码，发现内部已经有 `send_to_agent` 调用：

```python
# investigation_agent.py 中的代码
if false_positive_result:
    await self.send_to_agent("visualization_agent", security_event.model_dump())

# tracing_agent.py 中的代码  
if new_evidence:
    await self.send_to_agent("investigation_agent", {...})

# response_agent.py 中的代码
await self.send_to_agent("visualization_agent", result)
```

### 5.2 两种协作模式对比

| 特性 | 模式A：智能体自主调用 | 模式B：协调器统一调度 |
|------|---------------------|---------------------|
| **代码侵入** | 低，现有代码无需修改 | 需修改智能体，移除内部 `send_to_agent` |
| **状态管理** | 分散在各智能体中 | 集中在协调器，易于追踪 |
| **重试机制** | 各智能体自行实现 | 协调器统一实现 |
| **熔断保护** | 难以实现 | 协调器统一实现 |
| **监控审计** | 日志分散 | 统一入口，易于审计 |
| **灵活性** | 高，智能体可独立运行 | 依赖协调器 |

### 5.3 推荐方案：混合模式

保留智能体内部的 `send_to_agent` 调用，同时协调器也具备调度能力：

```python
# 智能体可以选择：
# 1. 内部调用下一个智能体（快速流转）
# 2. 返回结果，由协调器决定（需要重试/熔断时）

# investigation_agent.py
async def run(self, event_data):
    # ... 研判逻辑 ...
    
    if false_positive_result:
        # 误报快速流转，直接调用可视化
        return await self.send_to_agent("visualization_agent", security_event.model_dump())
    
    # 真实攻击，返回结果让协调器调度（便于重试/熔断）
    return {
        "result": "真实事件",
        "event_data": security_event.model_dump(),
        "next_agent": "tracing_agent"
    }
```

### 5.4 智能体返回格式规范

建议统一智能体返回格式：

```python
{
    "status": "success" | "failed",      # 执行状态
    "result": "真实事件" | "误报" | "...",  # 结果类型
    "event_id": "xxx",                   # 事件ID
    "event_data": {...},                 # 完整事件数据
    "next_agent": "agent_name",          # 建议下一个智能体（可选）
    "need_human_confirmation": False,    # 是否需要人工确认
    "need_reinvestigation": False,       # 是否需要重新研判（循环溯源）
    "error": "error message",            # 错误信息（失败时）
    "security_check": {                  # 安全校验结果（处置时）
        "risk_level": "low" | "high" | "critical",
        "warnings": [...]
    }
}
```

---

## 六、统一入口函数

### 6.1 入口函数设计

```python
# flows/security_event_flow.py

async def process_security_event(
    event_data: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    处理安全事件的统一入口函数
    
    Args:
        event_data: 安全事件数据，支持格式：
            - XDR告警原始格式
            - 人工录入格式
            - 标准化 SecurityEvent 格式
        config: 可选配置，覆盖默认值
    
    Returns:
        处理结果字典
    """
    orchestrator = SecurityEventOrchestrator()
    
    if config:
        # 应用配置覆盖
        if "max_retries" in config:
            orchestrator.max_retries = config["max_retries"]
        if "circuit_breaker_threshold" in config:
            orchestrator.circuit_breaker_threshold = config["circuit_breaker_threshold"]
    
    return await orchestrator.process_event(event_data)


async def continue_after_human_confirm(
    event_id: str,
    event_data: Dict[str, Any],
    approved: bool = True,
    comment: str = ""
) -> Dict[str, Any]:
    """
    人工确认后继续处理
    
    Args:
        event_id: 事件ID
        event_data: 事件数据
        approved: 是否批准执行
        comment: 人工备注
    
    Returns:
        处理结果
    """
    orchestrator = SecurityEventOrchestrator()
    return await orchestrator.continue_after_human_confirm(
        event_id, event_data, approved, comment
    )


async def get_event_status(event_id: str) -> Dict[str, Any]:
    """
    获取事件处理状态
    
    Args:
        event_id: 事件ID
    
    Returns:
        事件状态信息
    """
    orchestrator = SecurityEventOrchestrator()
    state = orchestrator.state_machine.get_state(event_id)
    history = orchestrator.state_machine.get_history(event_id)
    
    return {
        "event_id": event_id,
        "current_state": state.value,
        "history": history
    }
```

### 6.2 创建 root_agent

```python
# flows/security_event_flow.py 末尾

# 创建 root_agent 供 VeADK 框架启动
root_agent = SecurityEventOrchestrator()

# 或使用工厂函数
def create_root_agent(config: Optional[Dict] = None) -> SecurityEventOrchestrator:
    """创建 root_agent"""
    return SecurityEventOrchestrator(**config or {})

root_agent = create_root_agent()
```

---

## 七、需要修改的现有文件

### 7.1 main.py

```python
# main.py - 修改后
from flows.security_event_flow import root_agent

# VEADK 会自动加载 root_agent
```

### 7.2 agents/__init__.py

```python
# agents/__init__.py - 无需修改
# 继续导出四个专家智能体
```

### 7.3 flows/__init__.py（新建）

```python
# flows/__init__.py
"""智能体协作流程模块"""
from flows.security_event_flow import (
    SecurityEventOrchestrator,
    EventState,
    EventStateMachine,
    process_security_event,
    continue_after_human_confirm,
    get_event_status,
    root_agent,
)

__all__ = [
    "SecurityEventOrchestrator",
    "EventState",
    "EventStateMachine",
    "process_security_event",
    "continue_after_human_confirm",
    "get_event_status",
    "root_agent",
]
```

---

## 八、测试计划

### 8.1 单元测试

```python
# tests/unit/flows/test_security_event_flow.py

class TestEventStateMachine:
    """状态机测试"""
    
    def test_initial_state_is_new(self):
        """新事件初始状态为 NEW"""
        sm = EventStateMachine()
        assert sm.get_state("event-001") == EventState.NEW
    
    def test_valid_transition(self):
        """正常状态转换"""
        sm = EventStateMachine()
        sm.transition("event-001", EventState.INVESTIGATING)
        assert sm.get_state("event-001") == EventState.INVESTIGATING
    
    def test_invalid_transition_raises_error(self):
        """非法状态转换抛出异常"""
        sm = EventStateMachine()
        with pytest.raises(ValueError):
            sm.transition("event-001", EventState.COMPLETED)  # NEW 不能直接到 COMPLETED
    
    def test_history_tracking(self):
        """状态变更历史记录"""
        sm = EventStateMachine()
        sm.transition("event-001", EventState.INVESTIGATING, "开始研判")
        sm.transition("event-001", EventState.TRACING, "研判完成")
        
        history = sm.get_history("event-001")
        assert len(history) == 2
        assert history[0]["from_state"] == "new"
        assert history[0]["to_state"] == "investigating"


class TestSecurityEventOrchestrator:
    """协调器测试"""
    
    @pytest.mark.asyncio
    async def test_false_positive_flow(self):
        """误报流程测试"""
        orchestrator = SecurityEventOrchestrator()
        
        with patch.object(orchestrator, 'send_to_agent') as mock_send:
            # 模拟研判返回误报
            mock_send.return_value = {
                "result": "误报",
                "event_data": {"event_id": "test-001"}
            }
            
            result = await orchestrator.process_event({"event_id": "test-001"})
            
            # 应该调用 visualization_agent
            assert mock_send.call_count >= 1
    
    @pytest.mark.asyncio
    async def test_real_attack_flow(self):
        """真实攻击完整流程测试"""
        orchestrator = SecurityEventOrchestrator()
        
        with patch.object(orchestrator, 'send_to_agent') as mock_send:
            # 模拟各阶段返回
            mock_send.side_effect = [
                {"result": "真实事件", "event_data": {"event_id": "test-002"}},  # 研判
                {"result": "溯源完成", "event_data": {"event_id": "test-002"}},  # 溯源
                {"result": "处置完成", "event_data": {"event_id": "test-002"}},  # 处置
                {"result": "归档完成", "event_data": {"event_id": "test-002"}},  # 归档
            ]
            
            result = await orchestrator.process_event({"event_id": "test-002"})
            
            assert result.get("result") == "归档完成"
    
    @pytest.mark.asyncio
    async def test_retry_mechanism(self):
        """重试机制测试"""
        orchestrator = SecurityEventOrchestrator()
        orchestrator.max_retries = 3
        
        with patch.object(orchestrator, 'send_to_agent') as mock_send:
            # 前两次失败，第三次成功
            mock_send.side_effect = [
                Exception("网络超时"),
                Exception("网络超时"),
                {"result": "成功"}
            ]
            
            result = await orchestrator._execute_with_retry(
                "investigation_agent", {}, "test-003"
            )
            
            assert result["result"] == "成功"
            assert mock_send.call_count == 3
    
    @pytest.mark.asyncio
    async def test_circuit_breaker(self):
        """熔断机制测试"""
        orchestrator = SecurityEventOrchestrator()
        orchestrator.max_retries = 1
        orchestrator.circuit_breaker_threshold = 2
        
        with patch.object(orchestrator, 'send_to_agent') as mock_send:
            mock_send.side_effect = Exception("服务不可用")
            
            # 第一次触发熔断
            with pytest.raises(Exception, match="重试"):
                await orchestrator._execute_with_retry("test_agent", {}, "event-1")
            
            # 第二次触发熔断
            with pytest.raises(Exception, match="重试"):
                await orchestrator._execute_with_retry("test_agent", {}, "event-2")
            
            # 熔断器应该打开
            assert orchestrator.circuit_breaker_open.get("test_agent") == True
    
    @pytest.mark.asyncio
    async def test_human_confirmation(self):
        """人工确认测试"""
        orchestrator = SecurityEventOrchestrator()
        
        # 模拟高风险处置
        with patch.object(orchestrator, 'send_to_agent') as mock_send:
            mock_send.side_effect = [
                {"result": "真实事件"},  # 研判
                {"result": "溯源完成", "security_check": {"risk_level": "critical"}},  # 溯源
            ]
            
            result = await orchestrator.process_event({"event_id": "test-004"})
            
            assert result["status"] == "need_human"
            assert result["risk_level"] == "critical"
```

### 8.2 集成测试

使用真实告警数据（`docs&data_demo/example_alert.json`）：

```python
# tests/integration/test_flow_integration.py

class TestFlowIntegration:
    """流程集成测试"""
    
    @pytest.mark.asyncio
    async def test_real_xdr_alert_processing(self):
        """使用真实XDR告警测试完整流程"""
        # 加载真实告警数据
        with open("docs&data_demo/example_alert.json") as f:
            alert_data = json.load(f)
        
        # 执行处理
        result = await process_security_event(alert_data)
        
        # 验证结果
        assert result.get("status") in ["completed", "need_human", "failed"]
```

---

## 九、待确认问题清单

在开始开发前，需要确认以下问题：

### 9.1 架构相关

| # | 问题 | 选项 | 建议 |
|---|------|------|------|
| 1 | 智能体协作模式 | A. 智能体自主调用<br>B. 协调器统一调度<br>C. 混合模式 | C（混合模式） |
| 2 | 状态持久化 | A. 仅内存<br>B. Redis<br>C. 数据库 | A（内存，后续可扩展） |
| 3 | 协调器实例化 | A. 单例全局<br>B. 每次请求创建新实例 | A（单例，状态机需要保持状态） |

### 9.2 功能相关

| # | 问题 | 选项 | 建议 |
|---|------|------|------|
| 4 | 人工确认触发方式 | A. 返回状态等待<br>B. Webhook通知<br>C. 钉钉/企微通知 | A + C（返回状态 + 可选通知） |
| 5 | 熔断恢复方式 | A. 自动恢复（定时）<br>B. 人工重置 | A（自动恢复，可配置时间） |
| 6 | 循环溯源最大次数 | ? | 3次（避免无限循环） |

### 9.3 性能相关

| # | 问题 | 选项 | 建议 |
|---|------|------|------|
| 7 | 并发处理同一事件 | A. 允许<br>B. 拒绝 | B（拒绝，防止重复处理） |
| 8 | 单事件处理超时 | ? 秒 | 300秒（5分钟） |
| 9 | 全局并发限制 | ? 个事件同时处理 | 根据资源配置 |

---

## 十、开发步骤

完成确认后，按以下步骤开发：

1. [ ] 创建 `flows/__init__.py`
2. [ ] 创建 `flows/security_event_flow.py`（状态机 + 协调器 + 入口函数）
3. [ ] 修改现有智能体返回格式（可选）
4. [ ] 修改 `main.py` 引用 root_agent
5. [ ] 编写单元测试
6. [ ] 编写集成测试
7. [ ] 更新 TODO.md 标记完成

---

## 十一、文件清单

### 新建文件

| 文件路径 | 说明 |
|----------|------|
| `flows/__init__.py` | 模块导出 |
| `flows/security_event_flow.py` | 协调器 + 状态机 + 入口函数 |
| `tests/unit/flows/__init__.py` | 测试模块 |
| `tests/unit/flows/test_security_event_flow.py` | 单元测试 |

### 修改文件

| 文件路径 | 修改内容 |
|----------|----------|
| `main.py` | 引用 flows.root_agent |
| `agents/investigation_agent.py` | 统一返回格式（可选） |
| `agents/tracing_agent.py` | 统一返回格式（可选） |
| `agents/response_agent.py` | 统一返回格式（可选） |
| `agents/visualization_agent.py` | 统一返回格式（可选） |
| `TODO.md` | 标记 Phase 3 完成 |

---

## 十二、参考资源

- VEADK 官方文档：`rule.md`
- VEADK GitHub: https://github.com/volcengine/veadk-python
- 现有智能体实现：`agents/*.py`
- 现有工具实现：`tools/*.py`
- 告警示例数据：`docs&data_demo/example_alert.json`

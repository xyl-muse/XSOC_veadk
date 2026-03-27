"""事件总线单元测试"""
import pytest
import asyncio
from src.core.event_bus import EventBus, Events


def test_event_bus_initialization():
    """测试事件总线初始化"""
    bus = EventBus()
    assert bus is not None
    assert isinstance(bus, EventBus)


def test_event_subscribe_and_emit():
    """测试事件订阅和同步发布"""
    bus = EventBus()
    received_data = None

    def handler(data):
        nonlocal received_data
        received_data = data

    # 订阅事件
    bus.on("test.event", handler)

    # 发布事件
    test_data = {"key": "value"}
    bus.emit("test.event", test_data)

    # 验证接收
    assert received_data == test_data


def test_event_once():
    """测试单次订阅"""
    bus = EventBus()
    call_count = 0

    def handler():
        nonlocal call_count
        call_count += 1

    # 单次订阅
    bus.once("test.once", handler)

    # 发布多次
    bus.emit("test.once")
    bus.emit("test.once")
    bus.emit("test.once")

    # 验证只调用一次
    assert call_count == 1


def test_event_unsubscribe():
    """测试取消订阅"""
    bus = EventBus()
    call_count = 0

    def handler():
        nonlocal call_count
        call_count += 1

    # 订阅事件
    bus.on("test.unsubscribe", handler)
    bus.emit("test.unsubscribe")
    assert call_count == 1

    # 取消订阅
    bus.off("test.unsubscribe", handler)
    bus.emit("test.unsubscribe")
    assert call_count == 1  # 不会再调用


def test_get_all_events():
    """测试获取所有已注册事件"""
    bus = EventBus()

    def handler1(): pass
    def handler2(): pass

    bus.on("event1", handler1)
    bus.on("event2", handler2)

    events = bus.get_all_events()
    assert len(events) == 2
    assert "event1" in events
    "event2" in events


def test_get_event_handlers():
    """测试获取事件处理函数"""
    bus = EventBus()

    def handler(): pass

    bus.on("test.handlers", handler)
    handlers = bus.get_event_handlers("test.handlers")
    assert len(handlers) == 1
    assert handlers[0] == handler


@pytest.mark.asyncio
async def test_async_event_emit():
    """测试异步事件发布"""
    bus = EventBus()
    received_data = None
    event_processed = asyncio.Event()

    async def async_handler(data):
        nonlocal received_data
        received_data = data
        event_processed.set()

    # 订阅异步事件
    bus.on("test.async", async_handler)

    # 发布异步事件
    test_data = "async test"
    await bus.emit_async("test.async", test_data)

    # 等待处理完成
    await asyncio.wait_for(event_processed.wait(), timeout=1.0)
    assert received_data == test_data


@pytest.mark.asyncio
async def test_mixed_sync_async_handlers():
    """测试同步和异步处理函数混合"""
    bus = EventBus()
    sync_called = False
    async_called = False

    def sync_handler():
        nonlocal sync_called
        sync_called = True

    async def async_handler():
        nonlocal async_called
        async_called = True

    bus.on("test.mixed", sync_handler)
    bus.on("test.mixed", async_handler)

    await bus.emit_async("test.mixed")

    assert sync_called is True
    assert async_called is True


def test_events_constants():
    """测试事件常量定义"""
    assert hasattr(Events, "EVENT_CREATED") == "event.created"
    assert hasattr(Events, "EVENT_STATUS_CHANGED") == "event.status.changed"
    assert hasattr(Events, "EVENT_COMPLETED") == "event.completed"
    assert hasattr(Events, "AGENT_STARTED") == "agent.started"
    assert hasattr(Events, "TOOL_CALLED") == "tool.called"
    assert hasattr(Events, "SYSTEM_STARTED") == "system.started"

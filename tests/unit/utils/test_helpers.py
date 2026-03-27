"""工具函数单元测试"""
import json
import time
from datetime import datetime, timezone
from src.utils.helpers import (
    generate_uuid,
    generate_trace_id,
    get_current_time,
    timestamp_to_datetime,
    datetime_to_timestamp,
    safe_json_loads,
    safe_json_dumps,
    md5_hash,
    sha256_hash,
    truncate_string,
    mask_sensitive_data,
    retry,
)


def test_generate_uuid():
    """测试UUID生成"""
    uuid1 = generate_uuid()
    uuid2 = generate_uuid()
    assert isinstance(uuid1, str)
    assert len(uuid1) == 36  # UUID v7长度
    assert uuid1 != uuid2


def test_generate_trace_id():
    """测试追踪ID生成"""
    trace_id = generate_trace_id()
    assert isinstance(trace_id, str)
    assert len(trace_id) == 36


def test_get_current_time():
    """测试获取当前时间"""
    current_time = get_current_time()
    assert isinstance(current_time, str)
    assert current_time.endswith("Z")  # UTC时间格式
    # 验证可以解析为datetime
    dt = datetime.fromisoformat(current_time.replace("Z", "+00:00"))
    assert isinstance(dt, datetime)


def test_timestamp_datetime_conversion():
    """测试时间戳和datetime转换"""
    now = datetime.now(timezone.utc)
    timestamp = datetime_to_timestamp(now)
    assert isinstance(timestamp, float)

    dt = timestamp_to_datetime(timestamp)
    assert isinstance(dt, datetime)
    assert abs(dt.timestamp() - timestamp) < 0.001


def test_safe_json_loads():
    """测试安全JSON解析"""
    # 正常JSON
    json_str = '{"key": "value", "num": 123}'
    result = safe_json_loads(json_str)
    assert result == {"key": "value", "num": 123}

    # 异常JSON
    invalid_json = '{"key": "value", num: 123}'  # 缺少引号
    result = safe_json_loads(invalid_json, default={"default": "value"})
    assert result == {"default": "value"}

    # 非字符串输入
    result = safe_json_loads(None, default="default")
    assert result == "default"


def test_safe_json_dumps():
    """测试安全JSON序列化"""
    # 正常对象
    obj = {"key": "value", "num": 123, "中文": "测试"}
    json_str = safe_json_dumps(obj, ensure_ascii=False)
    assert "中文" in json_str
    assert json.loads(json_str) == obj

    # 不可序列化对象
    class Unserializable:
        pass

    obj = {"key": Unserializable()}
    json_str = safe_json_dumps(obj)
    assert json_str == ""


def test_hash_functions():
    """测试哈希函数"""
    test_str = "测试字符串"

    md5 = md5_hash(test_str)
    assert isinstance(md5, str)
    assert len(md5) == 32

    sha256 = sha256_hash(test_str)
    assert isinstance(sha256, str)
    assert len(sha256) == 64


def test_truncate_string():
    """测试字符串截断"""
    long_str = "这是一个很长的字符串，用来测试截断功能"
    # 短字符串不截断
    assert truncate_string(long_str, max_length=100) == long_str
    # 长字符串截断
    truncated = truncate_string(long_str, max_length=10)
    assert len(truncated) == 10
    assert truncated.endswith("...")
    # 自定义后缀
    truncated = truncate_string(long_str, max_length=10, suffix="~")
    assert len(truncated) == 10
    assert truncated.endswith("~")


def test_mask_sensitive_data():
    """测试敏感数据掩码"""
    data = {
        "api_key": "abcdefghijklmnopqrstuvwxyz123456",
        "password": "mypassword123",
        "token": "token1234567890",
        "normal_field": "正常字段",
        "nested": {
            "secret_key": "secret123456"
        }
    }

    masked = mask_sensitive_data(data)
    # 敏感字段被掩码
    assert masked["api_key"] == "abcd****3456"
    assert masked["password"] == "****"
    assert masked["token"] == "****"
    assert masked["nested"]["secret_key"] == "secr****456"
    # 普通字段不变
    assert masked["normal_field"] == "正常字段"


def test_retry_decorator_sync():
    """测试同步重试装饰器"""
    call_count = 0

    @retry(times=3, delay=0.01)
    def flaky_function():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise Exception("临时错误")
        return "success"

    result = flaky_function()
    assert result == "success"
    assert call_count == 3


def test_retry_decorator_async():
    """测试异步重试装饰器"""
    call_count = 0

    @retry(times=3, delay=0.01)
    async def flaky_async_function():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise Exception("临时错误")
        return "success"

    import asyncio
    result = asyncio.run(flaky_async_function())
    assert result == "success"
    assert call_count == 3


def test_retry_decorator_fail():
    """测试重试失败情况"""
    call_count = 0

    @retry(times=3, delay=0.01)
    def always_fail():
        nonlocal call_count
        call_count += 1
        raise Exception("永久错误")

    try:
        always_fail()
    except Exception as e:
        assert "永久错误" in str(e)
    assert call_count == 3

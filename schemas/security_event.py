"""安全事件标准化数据模型"""
from enum import Enum
from datetime import datetime
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

from src.utils.helpers import generate_uuid, get_current_time


class EventType(str, Enum):
    """事件类型枚举"""
    SERVER_SECURITY = "server_security"
    ENDPOINT_SECURITY = "endpoint_security"
    ICS_SECURITY = "ics_security"
    PHISHING_EMAIL = "phishing_email"
    NETWORK_ATTACK = "network_attack"
    DATA_LEAK = "data_leak"
    PERSONAL_INFO = "personal_info"
    PUBLIC_OPINION = "public_opinion"
    OTHER = "other"

    @property
    def display_name(self) -> str:
        """中文名称"""
        name_map = {
            self.SERVER_SECURITY: "服务器安全事件",
            self.ENDPOINT_SECURITY: "办公终端安全事件",
            self.ICS_SECURITY: "工控终端安全事件",
            self.PHISHING_EMAIL: "钓鱼邮件及电诈事件",
            self.NETWORK_ATTACK: "网络流量攻击事件",
            self.DATA_LEAK: "失泄密事件",
            self.PERSONAL_INFO: "个人信息事件",
            self.PUBLIC_OPINION: "舆情事件",
            self.OTHER: "其他安全事件",
        }
        return name_map.get(self, "未知事件类型")


class EventStatus(str, Enum):
    """事件状态枚举"""
    PENDING = "pending"
    INVESTIGATING = "investigating"
    TRACING = "tracing"
    RESPONDING = "responding"
    VISUALIZING = "visualizing"
    COMPLETED = "completed"
    FAILED = "failed"
    FALSE_POSITIVE = "false_positive"
    PENDING_MANUAL_CONFIRM = "pending_manual_confirm"

    @property
    def display_name(self) -> str:
        """中文名称"""
        name_map = {
            self.PENDING: "待处理",
            self.INVESTIGATING: "研判中",
            self.TRACING: "溯源中",
            self.RESPONDING: "处置中",
            self.VISUALIZING: "报告生成中",
            self.COMPLETED: "已完成",
            self.FAILED: "处理失败",
            self.FALSE_POSITIVE: "误报",
            self.PENDING_MANUAL_CONFIRM: "待人工确认",
        }
        return name_map.get(self, "未知状态")


class Priority(str, Enum):
    """事件优先级枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def display_name(self) -> str:
        """中文名称"""
        name_map = {
            self.LOW: "低",
            self.MEDIUM: "中",
            self.HIGH: "高",
            self.CRITICAL: "严重",
        }
        return name_map.get(self, "未知")


class ProcessHistoryItem(BaseModel):
    """处理历史记录项"""
    stage: str = Field(description="处理阶段标识")
    stage_name: str = Field(description="处理阶段中文名称")
    agent: str = Field(description="处理智能体标识")
    agent_name: str = Field(description="处理智能体中文名称")
    start_time: str = Field(default_factory=get_current_time, description="开始时间")
    end_time: Optional[str] = Field(None, description="结束时间")
    status: str = Field(description="处理结果状态")
    status_name: str = Field(description="处理结果状态中文名称")
    result: Any = Field(description="处理结果")
    logs: List[str] = Field(default_factory=list, description="处理日志")


class SecurityEvent(BaseModel):
    """标准化安全事件数据模型"""
    event_id: str = Field(default_factory=generate_uuid, description="全局唯一事件ID")
    trace_id: str = Field(default_factory=generate_uuid, description="全链路追踪ID")
    event_type: EventType = Field(description="事件类型枚举值")
    event_type_name: str = Field(description="事件类型中文名称")
    source: str = Field(description="事件来源：xdr_api, manual_input等")
    source_name: str = Field(description="事件来源中文名称")
    raw_data: Dict[str, Any] = Field(description="原始数据")
    status: EventStatus = Field(default=EventStatus.PENDING, description="当前状态枚举值")
    status_name: str = Field(default=EventStatus.PENDING.display_name, description="当前状态中文名称")
    current_agent: Optional[str] = Field(None, description="当前处理智能体标识")
    current_agent_name: Optional[str] = Field(None, description="当前处理智能体中文名称")
    priority: Priority = Field(default=Priority.MEDIUM, description="优先级枚举值")
    priority_name: str = Field(default=Priority.MEDIUM.display_name, description="优先级中文名称")
    create_time: str = Field(default_factory=get_current_time, description="事件创建时间")
    update_time: str = Field(default_factory=get_current_time, description="最后更新时间")
    process_history: List[ProcessHistoryItem] = Field(default_factory=list, description="处理历史记录")
    context: Dict[str, Any] = Field(default_factory=dict, description="上下文信息")
    error_info: Optional[Dict[str, Any]] = Field(None, description="错误信息")
    attack_source_ip: Optional[str] = Field(None, description="攻击源IP")
    target_asset_ip: Optional[str] = Field(None, description="目标资产IP")
    attack_time: Optional[str] = Field(None, description="攻击发生时间")

    @classmethod
    def from_input(cls, input_data: Dict[str, Any]) -> "SecurityEvent":
        """从输入数据创建事件实例"""
        # 处理事件类型
        event_type = input_data.get("event_type")
        if isinstance(event_type, str):
            try:
                event_type = EventType(event_type)
            except ValueError:
                event_type = EventType.OTHER

        # 处理来源
        source = input_data.get("source", "manual_input")
        source_name = "XDR系统推送" if source == "xdr_api" else "人工录入"

        # 自动提取IP信息
        attack_source_ip = input_data.get("attack_source_ip") or cls._extract_ip(input_data.get("raw_data", {}), "source")
        target_asset_ip = input_data.get("target_asset_ip") or cls._extract_ip(input_data.get("raw_data", {}), "target")

        return cls(
            event_type=event_type,
            event_type_name=event_type.display_name,
            source=source,
            source_name=source_name,
            raw_data=input_data.get("raw_data", {}),
            attack_source_ip=attack_source_ip,
            target_asset_ip=target_asset_ip,
            attack_time=input_data.get("attack_time"),
        )

    @staticmethod
    def _extract_ip(data: Dict[str, Any], ip_type: str) -> Optional[str]:
        """从原始数据中提取IP地址"""
        ip_keys = [f"{ip_type}_ip", f"{ip_type}Ip", ip_type, f"src_ip" if ip_type == "source" else f"dst_ip"]
        for key in ip_keys:
            if key in data and isinstance(data[key], str) and len(data[key]) > 0:
                return data[key]
        return None

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """重写dump方法，自动更新update_time和status_name"""
        self.update_time = get_current_time()
        self.status_name = self.status.display_name
        self.priority_name = self.priority.display_name
        return super().model_dump(**kwargs)

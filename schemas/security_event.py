"""安全事件标准化数据模型"""
from enum import Enum
from datetime import datetime
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
import re

import uuid
from datetime import datetime


def generate_uuid() -> str:
    """生成唯一UUID"""
    return str(uuid.uuid4())


def get_current_time() -> str:
    """获取当前时间字符串，格式：YYYY-MM-DD HH:MM:SS"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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
    """事件状态枚举（15种状态，覆盖全流程场景）"""
    # 初始阶段
    PENDING = "pending"                      # 待处理
    VALIDATING = "validating"                # 格式校验中

    # 研判阶段
    INVESTIGATING = "investigating"          # 研判中
    FALSE_POSITIVE = "false_positive"        # 误报

    # 溯源阶段
    TRACING = "tracing"                      # 溯源中

    # 处置阶段
    PROCESSING = "processing"                # 处置中（策略生成）
    VALIDATING_DISPOSAL = "validating_disposal"  # 处置校验中
    PENDING_APPROVAL = "pending_approval"    # 待人工审核
    EXECUTING_DISPOSAL = "executing_disposal"    # 处置执行中
    VERIFYING_DISPOSAL = "verifying_disposal"    # 处置验证中

    # 归档阶段
    VISUALIZING = "visualizing"              # 报告生成中
    ARCHIVING = "archiving"                  # 归档中

    # 终态
    COMPLETED = "completed"                  # 已完成
    FAILED = "failed"                        # 处理失败
    CLOSED = "closed"                        # 已关闭（人工关闭）

    # 兼容旧状态（已废弃，保留向后兼容）
    RESPONDING = "responding"                # 废弃：使用 PROCESSING
    ARCHIVED = "archived"                    # 废弃：使用 COMPLETED
    PENDING_MANUAL_CONFIRM = "pending_manual_confirm"  # 废弃：使用 PENDING_APPROVAL

    @property
    def display_name(self) -> str:
        """中文名称"""
        name_map = {
            self.PENDING: "待处理",
            self.VALIDATING: "格式校验中",
            self.INVESTIGATING: "研判中",
            self.FALSE_POSITIVE: "误报",
            self.TRACING: "溯源中",
            self.PROCESSING: "处置中",
            self.VALIDATING_DISPOSAL: "处置校验中",
            self.PENDING_APPROVAL: "待人工审核",
            self.EXECUTING_DISPOSAL: "处置执行中",
            self.VERIFYING_DISPOSAL: "处置验证中",
            self.VISUALIZING: "报告生成中",
            self.ARCHIVING: "归档中",
            self.COMPLETED: "已完成",
            self.FAILED: "处理失败",
            self.CLOSED: "已关闭",
            # 兼容旧状态
            self.RESPONDING: "处置中",
            self.ARCHIVED: "已归档",
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
        """从输入数据创建事件实例，支持XDR多格式告警适配和自然语言解析"""
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

        # 获取原始数据
        raw_data = input_data.get("raw_data", {})

        # 自动提取IP信息（支持XDR多格式告警适配）
        attack_source_ip = input_data.get("attack_source_ip") or cls._extract_ip(raw_data, "source")
        target_asset_ip = input_data.get("target_asset_ip") or cls._extract_ip(raw_data, "target")

        # 自动提取事件ID（支持uuId/hostIp/riskTag等XDR原生字段）
        event_id = input_data.get("event_id") or raw_data.get("event_id") or raw_data.get("uuId") or raw_data.get("alert_id")

        # 自动提取攻击时间（支持Unix时间戳转换）
        attack_time = input_data.get("attack_time") or raw_data.get("attack_time") or raw_data.get("create_time")
        if attack_time:
            if isinstance(attack_time, int) or (isinstance(attack_time, str) and attack_time.isdigit()):
                # 处理Unix时间戳
                try:
                    timestamp = int(attack_time)
                    if timestamp > 1000000000000:
                        timestamp = timestamp / 1000  # 毫秒转秒
                    attack_time = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                except:
                    pass

        # 自动提取风险标签和威胁定义名称
        risk_tags = raw_data.get("riskTag") or raw_data.get("risk_tags", [])
        if isinstance(risk_tags, str):
            risk_tags = [risk_tags]

        threat_define_name = raw_data.get("threatDefineName") or raw_data.get("threat_define_name", "")

        # 自动提取优先级
        priority = input_data.get("priority", Priority.MEDIUM)
        if isinstance(priority, str):
            priority = priority.lower()
            if priority in ["low", "medium", "high", "critical"]:
                priority = Priority(priority)
            else:
                try:
                    priority_level = int(priority)
                    if priority_level >= 3:
                        priority = Priority.CRITICAL
                    elif priority_level == 2:
                        priority = Priority.HIGH
                    elif priority_level == 1:
                        priority = Priority.MEDIUM
                    else:
                        priority = Priority.LOW
                except:
                    priority = Priority.MEDIUM

        # 创建事件实例
        event = cls(
            event_id=event_id,
            event_type=event_type,
            event_type_name=event_type.display_name,
            source=source,
            source_name=source_name,
            raw_data=raw_data,
            attack_source_ip=attack_source_ip,
            target_asset_ip=target_asset_ip,
            attack_time=attack_time,
            priority=priority,
        )

        # 保存提取到的额外字段到上下文
        event.context["risk_tags"] = risk_tags
        event.context["threat_define_name"] = threat_define_name
        event.context["gpt_result"] = raw_data.get("gptResult") or raw_data.get("gpt_result", "")

        return event

    @staticmethod
    def _extract_ip(data: Dict[str, Any], ip_type: str) -> Optional[str]:
        """从原始数据中提取IP地址，支持XDR多格式告警适配"""
        # 基础IP字段
        ip_keys = [
            f"{ip_type}_ip", f"{ip_type}Ip", ip_type,
            f"src_ip" if ip_type == "source" else f"dst_ip"
        ]

        # XDR扁平结构字段
        xdr_flat_keys = [
            "attack_source_ip", "attackSourceIp", "source_ip", "sourceIp",
            "target_asset_ip", "targetAssetIp", "target_ip", "targetIp"
        ]

        # XDR state嵌套结构字段
        xdr_state_keys = [
            "state.attack_source_ip", "state.attackSourceIp", "state.source_ip", "state.sourceIp",
            "state.target_asset_ip", "state.targetAssetIp", "state.target_ip", "state.targetIp"
        ]

        # 遍历基础字段
        for key in ip_keys:
            if key in data and isinstance(data[key], str) and len(data[key]) > 0:
                return data[key]

        # 遍历XDR扁平结构字段
        for key in xdr_flat_keys:
            if key in data and isinstance(data[key], str) and len(data[key]) > 0:
                # 根据ip_type筛选相关字段
                if (ip_type == "source" and "source" in key) or (ip_type == "target" and "target" in key):
                    return data[key]

        # 遍历XDR state嵌套结构字段
        for key in xdr_state_keys:
            parts = key.split(".")
            value = data
            for part in parts:
                if part in value:
                    value = value[part]
                else:
                    break
            else:
                if isinstance(value, str) and len(value) > 0:
                    return value

        # 从原始数据中尝试其他可能的字段
        for key, value in data.items():
            if isinstance(value, str) and len(value) > 0:
                # 简单的IP地址匹配（IPv4）
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
                    # 根据key名称判断是否与ip_type相关
                    if (ip_type == "source" and any(s in key.lower() for s in ["source", "src", "attack"])) or \
                       (ip_type == "target" and any(t in key.lower() for t in ["target", "dst", "asset"])) or \
                       ip_type not in ["source", "target"]:
                        return value

        return None

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """重写dump方法，自动更新update_time和status_name"""
        self.update_time = get_current_time()
        self.status_name = self.status.display_name
        self.priority_name = self.priority.display_name
        return super().model_dump(**kwargs)

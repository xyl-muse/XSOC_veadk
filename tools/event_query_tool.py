"""事件信息查询工具
融合XDR、NDR两个平台的事件查询接口，支持多平台结果合并
优先级：XDR > NDR，优先查询XDR平台事件信息
"""
import os
import httpx
from typing import Optional, Dict, Any, List
import asyncio
from google.adk.tools.tool_context import ToolContext


def _get_config():
    """从环境变量获取工具配置"""
    # NDR多实例配置
    ndr_instances = {}
    
    # NDR_NORTH 实例（集团北数据中心）
    if os.getenv("NDR_NORTH_BASE_URL"):
        ndr_instances["ndr_north"] = {
            "enabled": os.getenv("NDR_NORTH_ENABLED", "true").lower() == "true",
            "base_url": os.getenv("NDR_NORTH_BASE_URL", ""),
            "api_key": os.getenv("NDR_NORTH_API_KEY", ""),
            "api_secret": os.getenv("NDR_NORTH_API_SECRET", ""),
        }
    
    # NDR_SOUTH 实例（集团南数据中心）
    if os.getenv("NDR_SOUTH_BASE_URL"):
        ndr_instances["ndr_south"] = {
            "enabled": os.getenv("NDR_SOUTH_ENABLED", "true").lower() == "true",
            "base_url": os.getenv("NDR_SOUTH_BASE_URL", ""),
            "api_key": os.getenv("NDR_SOUTH_API_KEY", ""),
            "api_secret": os.getenv("NDR_SOUTH_API_SECRET", ""),
        }
    
    # 向后兼容：支持旧版单实例配置
    if not ndr_instances and os.getenv("NDR_API_BASE_URL"):
        ndr_instances["ndr"] = {
            "enabled": os.getenv("NDR_ENABLED", "true").lower() == "true",
            "base_url": os.getenv("NDR_API_BASE_URL", os.getenv("NDR_BASE_URL", "")),
            "api_key": os.getenv("NDR_API_KEY", ""),
            "api_secret": os.getenv("NDR_API_SECRET", ""),
        }
    
    return {
        "xdr": {
            "enabled": os.getenv("XDR_ENABLED", "true").lower() == "true",
            "base_url": os.getenv("XDR_API_BASE_URL", os.getenv("XDR_BASE_URL", "")),
            "api_key": os.getenv("XDR_API_KEY", ""),
        },
        "ndr_instances": ndr_instances,
    }


async def event_query(
    event_id: Optional[str] = None,
    event_ids: Optional[List[str]] = None,
    start_time: Optional[int] = None,
    end_time: Optional[int] = None,
    platform: str = "all",
    page: int = 1,
    page_size: int = 10,
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    事件信息查询工具
    查询安全事件的详情、举证信息、进程实体、事件关联信息，支持多平台数据融合
    优先级：XDR > NDR

    Args:
        event_id: 要查询的事件ID，查询单个事件详情时使用
        event_ids: 要查询的事件ID列表，批量查询时使用
        start_time: 查询起始时间戳，单位秒，默认最近7天
        end_time: 查询结束时间戳，单位秒，默认当前时间
        platform: 查询平台选择
            - xdr: XDR平台（优先）
            - ndr: NDR平台
            - all: 按优先级查询所有平台（默认）
        page: 页码，默认1
        page_size: 每页数量，默认10
        tool_context: 运行时上下文（可选）

    Returns:
        包含事件信息的字典，自动合并多平台结果
    """
    config = _get_config()
    timeout = 30

    # XDR平台配置
    xdr_enabled = config["xdr"]["enabled"]
    xdr_base_url = config["xdr"]["base_url"]
    xdr_api_key = config["xdr"]["api_key"]

    # NDR平台配置
    ndr_enabled = config["ndr"]["enabled"]
    ndr_base_url = config["ndr"]["base_url"]
    ndr_api_key = config["ndr"]["api_key"]

    platform = platform.lower()

    # 收集需要查询的平台，严格按照优先级顺序：XDR > NDR
    platforms_to_query = []
    if platform == "all":
        if xdr_enabled:
            platforms_to_query.append("xdr")
        if ndr_enabled:
            platforms_to_query.append("ndr")
    else:
        platforms_to_query = [platform]

    if not platforms_to_query:
        return {"error": "没有可用的查询平台，请检查配置"}

    # 并发查询所有平台
    tasks = []
    query_params = {
        "event_id": event_id,
        "event_ids": event_ids,
        "start_time": start_time,
        "end_time": end_time,
        "page": page,
        "page_size": page_size
    }

    for p in platforms_to_query:
        if p == "xdr":
            tasks.append(_query_xdr_event(query_params, xdr_base_url, xdr_api_key, timeout))
        elif p == "ndr":
            tasks.append(_query_ndr_event(query_params, ndr_base_url, ndr_api_key, timeout))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 处理查询结果
    platform_results = {}
    for i, p in enumerate(platforms_to_query):
        result = results[i]
        if isinstance(result, Exception):
            platform_results[p] = {"error": str(result)}
        else:
            platform_results[p] = result

    # 合并结果
    merged_result = _merge_event_results(platform_results)

    return {
        "query_params": query_params,
        "platforms_queried": platforms_to_query,
        "platform_results": platform_results,
        "merged_result": merged_result
    }


async def _query_xdr_event(query_params: Dict[str, Any], base_url: str, api_key: str, timeout: int) -> Dict[str, Any]:
    """查询XDR平台事件信息（优先级最高）"""
    if not base_url or not api_key:
        return {"error": "XDR平台配置不完整"}

    try:
        url = f"{base_url}/api/xdr/v1/incidents/list"
        headers = {"Authorization": f"Bearer {api_key}"}

        payload = {
            "page": query_params["page"],
            "pageSize": query_params["page_size"]
        }

        # 处理时间范围
        if query_params["start_time"]:
            payload["startTimestamp"] = query_params["start_time"]
        if query_params["end_time"]:
            payload["endTimestamp"] = query_params["end_time"]

        # 处理事件ID查询
        if query_params["event_id"]:
            payload["uuIds"] = [query_params["event_id"]]
        elif query_params["event_ids"]:
            payload["uuIds"] = query_params["event_ids"]

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != "Success":
            return {
                "error": f"查询失败: {data.get('message', '未知错误')}"
            }

        result_data = data.get("data", {})
        if not result_data or not result_data.get("item"):
            return {"error": "XDR平台未查询到事件信息"}

        # 解析XDR结果
        parsed_events = [_parse_xdr_event_item(item) for item in result_data["item"]]

        return {
            "platform": "xdr",
            "total": result_data.get("total", 0),
            "page": result_data.get("page", 1),
            "page_size": result_data.get("pageSize", 10),
            "events": parsed_events
        }

    except Exception as e:
        return {"error": f"XDR查询异常: {str(e)}"}


async def _query_ndr_event(query_params: Dict[str, Any], base_url: str, api_key: str, timeout: int) -> Dict[str, Any]:
    """查询NDR平台事件信息"""
    if not base_url or not api_key:
        return {"error": "NDR平台配置不完整"}

    try:
        # 优先查询事件详情，否则查询事件列表
        if query_params["event_id"] or query_params["event_ids"]:
            url = f"{base_url}/api/v1/incident/result"
            payload = {
                "incident_id": query_params["event_id"] or query_params["event_ids"][0]
            }
        else:
            url = f"{base_url}/api/v1/incident/search"
            payload = {
                "page": query_params["page"],
                "page_size": query_params["page_size"]
            }
            if query_params["start_time"]:
                payload["start_time"] = query_params["start_time"]
            if query_params["end_time"]:
                payload["end_time"] = query_params["end_time"]

        params = {
            "api_key": api_key,
            "auth_timestamp": str(int(asyncio.get_event_loop().time())),
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != 0:
            return {
                "error": f"查询失败: {data.get('message', '未知错误')}"
            }

        result_data = data.get("data", {})
        if not result_data:
            return {"error": "NDR平台未查询到事件信息"}

        # 解析NDR结果
        if isinstance(result_data, list):
            parsed_events = [_parse_ndr_event_item(item) for item in result_data]
            total = len(parsed_events)
        else:
            parsed_events = [_parse_ndr_event_item(result_data)]
            total = 1

        return {
            "platform": "ndr",
            "total": total,
            "page": query_params["page"],
            "page_size": query_params["page_size"],
            "events": parsed_events
        }

    except Exception as e:
        return {"error": f"NDR查询异常: {str(e)}"}


def _parse_xdr_event_item(data: Dict[str, Any]) -> Dict[str, Any]:
    """解析XDR事件条目"""
    severity_map = {0: "信息", 1: "低危", 2: "中危", 3: "高危", 4: "严重"}
    deal_status_map = {0: "待处置", 1: "处理中", 2: "已处置", 3: "已忽略", 4: "误报"}

    return {
        "event_id": data.get("uuId", ""),
        "event_name": data.get("name", ""),
        "description": data.get("description", ""),
        "severity": data.get("incidentSeverity", 0),
        "severity_name": severity_map.get(data.get("incidentSeverity", 0), "未知"),
        "host_ip": data.get("hostIp", ""),
        "host_asset_id": data.get("hostAssetId", ""),
        "branch_name": data.get("branchName", ""),
        "host_groups": data.get("hostGroups", []),
        "threat_type": data.get("incidentThreatType", ""),
        "threat_category": data.get("incidentThreatClass", ""),
        "risk_tags": data.get("riskTag", []),
        "start_time": data.get("startTime", 0),
        "end_time": data.get("endTime", 0),
        "alert_ids": data.get("alertIds", []),
        "deal_status": data.get("dealStatus", 0),
        "deal_status_name": deal_status_map.get(data.get("dealStatus", 0), "未知"),
        "data_sources": data.get("dataSource", []),
        "gpt_result": data.get("gptResult", 0),
        "gpt_result_desc": data.get("gptResultDescription", "")
    }


def _parse_ndr_event_item(data: Dict[str, Any]) -> Dict[str, Any]:
    """解析NDR事件条目"""
    severity_map = {1: "低危", 2: "中危", 3: "高危", 4: "严重"}

    return {
        "event_id": data.get("incident_id", data.get("id", "")),
        "event_name": data.get("event_name", data.get("title", "")),
        "description": data.get("description", ""),
        "severity": data.get("severity", data.get("risk_level", 1)),
        "severity_name": severity_map.get(data.get("severity", data.get("risk_level", 1)), "未知"),
        "source_ip": data.get("src_ip", ""),
        "destination_ip": data.get("dst_ip", ""),
        "attack_type": data.get("attack_type", ""),
        "risk_tags": data.get("risk_tags", data.get("tags", [])),
        "occur_time": data.get("occur_time", data.get("timestamp", 0)),
        "alert_count": data.get("alert_count", 0),
        "deal_status": data.get("deal_status", 0),
        "evidence": data.get("evidence", {})
    }


def _merge_event_results(platform_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """合并多平台事件信息，优先级高的平台数据权重更高"""
    merged = {
        "total": 0,
        "events": [],
        "source_platforms": [],
        "confidence": 0
    }

    # 优先级权重：XDR 0.7, NDR 0.3
    weight_map = {
        "xdr": 0.7,
        "ndr": 0.3
    }

    # 按优先级顺序处理：XDR > NDR
    priority_order = ["xdr", "ndr"]
    all_events = []

    for platform in priority_order:
        if platform not in platform_results:
            continue

        result = platform_results[platform]
        if "error" in result:
            continue

        merged["source_platforms"].append(platform)
        weight = weight_map.get(platform, 0)
        merged["confidence"] += int(weight * 100)

        # 收集所有事件
        events = result.get("events", [])
        for event in events:
            event["source_platform"] = platform
            all_events.append(event)

    # 去重：相同event_id的事件保留高优先级平台的数据
    unique_events = {}
    for event in all_events:
        event_id = event["event_id"]
        if event_id not in unique_events:
            unique_events[event_id] = event
        else:
            # 高优先级平台的数据保留，合并低优先级平台的补充字段
            existing = unique_events[event_id]
            for key, value in event.items():
                if key not in existing or not existing[key]:
                    existing[key] = value

    merged["events"] = list(unique_events.values())
    merged["total"] = len(merged["events"])

    # 如果没有任何有效结果
    if not merged["source_platforms"]:
        return {
            "error": "所有平台均未查询到事件信息",
            "confidence": 0
        }

    return merged

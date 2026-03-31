"""告警及风险信息查询工具
融合XDR、NDR、Corplink三个平台的告警及风险查询接口，支持多平台结果合并
"""
import os
import httpx
from typing import Optional, Dict, Any, List
import asyncio
from google.adk.tools.tool_context import ToolContext


def _get_config():
    """从环境变量获取工具配置"""
    return {
        "xdr": {
            "enabled": os.getenv("XDR_ENABLED", "true").lower() == "true",
            "base_url": os.getenv("XDR_API_BASE_URL", os.getenv("XDR_BASE_URL", "")),
            "api_key": os.getenv("XDR_API_KEY", ""),
        },
        "ndr": {
            "enabled": os.getenv("NDR_ENABLED", "true").lower() == "true",
            "base_url": os.getenv("NDR_API_BASE_URL", os.getenv("NDR_BASE_URL", "")),
            "api_key": os.getenv("NDR_API_KEY", ""),
        },
        "corplink": {
            "enabled": os.getenv("CORPLINK_ENABLED", "true").lower() == "true",
            "base_url": os.getenv("CORPLINK_BASE_URL", ""),
            "api_key": os.getenv("CORPLINK_API_KEY", ""),
        },
    }


async def alert_risk_query(
    asset_ip: Optional[str] = None,
    time_range: str = "24h",
    alert_type: Optional[str] = None,
    severity: Optional[List[str]] = None,
    platform: str = "all",
    page: int = 1,
    page_size: int = 10,
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    告警及风险信息查询工具
    查询告警详情、风险信息、安全态势、调查分析相关数据，支持多平台数据融合

    Args:
        asset_ip: 要查询的资产IP地址，查询特定资产的告警时使用
        time_range: 查询时间范围，支持格式：1h/24h/7d/30d或时间戳范围，默认24h
        alert_type: 告警类型筛选，可选值：malware/attack/abnormal/policy等
        severity: 告警级别筛选：info/low/medium/high/critical
        platform: 查询平台选择：xdr/ndr/corplink/all，默认all
        page: 页码，默认1
        page_size: 每页数量，默认10
        tool_context: 运行时上下文（可选）

    Returns:
        包含告警信息的字典，自动合并多平台结果
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

    # Corplink平台配置
    corplink_enabled = config["corplink"]["enabled"]
    corplink_base_url = config["corplink"]["base_url"]
    corplink_api_key = config["corplink"]["api_key"]

    platform = platform.lower()

    # 收集需要查询的平台
    platforms_to_query = []
    if platform == "all":
        if xdr_enabled:
            platforms_to_query.append("xdr")
        if ndr_enabled:
            platforms_to_query.append("ndr")
        if corplink_enabled:
            platforms_to_query.append("corplink")
    else:
        platforms_to_query = [platform]

    if not platforms_to_query:
        return {"error": "没有可用的查询平台，请检查配置"}

    # 解析时间范围
    start_time, end_time = _parse_time_range(time_range)

    # 并发查询所有平台
    tasks = []
    query_params = {
        "asset_ip": asset_ip,
        "start_time": start_time,
        "end_time": end_time,
        "alert_type": alert_type,
        "severity": severity,
        "page": page,
        "page_size": page_size
    }

    for p in platforms_to_query:
        if p == "xdr":
            tasks.append(_query_xdr_alert(query_params, xdr_base_url, xdr_api_key, timeout))
        elif p == "ndr":
            tasks.append(_query_ndr_alert(query_params, ndr_base_url, ndr_api_key, timeout))
        elif p == "corplink":
            tasks.append(_query_corplink_alert(query_params, corplink_base_url, corplink_api_key, timeout))

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
    merged_result = _merge_alert_results(platform_results)

    return {
        "query_params": query_params,
        "platforms_queried": platforms_to_query,
        "platform_results": platform_results,
        "merged_result": merged_result
    }


def _parse_time_range(time_range: str) -> tuple:
    """解析时间范围，返回起始和结束时间戳（秒）"""
    import time
    now = int(time.time())

    if time_range.endswith("h"):
        hours = int(time_range[:-1])
        start_time = now - hours * 3600
    elif time_range.endswith("d"):
        days = int(time_range[:-1])
        start_time = now - days * 86400
    elif "-" in time_range:
        # 时间戳范围，格式：start-end
        start_str, end_str = time_range.split("-", 1)
        start_time = int(start_str)
        end_time = int(end_str)
        return start_time, end_time
    else:
        # 默认24小时
        start_time = now - 86400

    return start_time, now


async def _query_xdr_alert(query_params: Dict[str, Any], base_url: str, api_key: str, timeout: int) -> Dict[str, Any]:
    """查询XDR平台告警信息"""
    if not base_url or not api_key:
        return {"error": "XDR平台配置不完整"}

    try:
        url = f"{base_url}/api/xdr/v1/alerts/list"
        headers = {"Authorization": f"Bearer {api_key}"}

        payload = {
            "page": query_params["page"],
            "pageSize": query_params["page_size"],
            "startTimestamp": query_params["start_time"] * 1000,  # XDR使用毫秒时间戳
            "endTimestamp": query_params["end_time"] * 1000
        }

        # 资产IP筛选
        if query_params["asset_ip"]:
            payload["hostIps"] = [query_params["asset_ip"]]

        # 级别筛选
        if query_params["severity"]:
            severity_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            payload["severities"] = [severity_map.get(s.lower(), 0) for s in query_params["severity"]]

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
            return {"error": "XDR平台未查询到告警信息"}

        # 解析XDR结果
        parsed_alerts = [_parse_xdr_alert_item(item) for item in result_data["item"]]

        return {
            "platform": "xdr",
            "total": result_data.get("total", 0),
            "page": result_data.get("page", 1),
            "page_size": result_data.get("pageSize", 10),
            "alerts": parsed_alerts
        }

    except Exception as e:
        return {"error": f"XDR查询异常: {str(e)}"}


async def _query_ndr_alert(query_params: Dict[str, Any], base_url: str, api_key: str, timeout: int) -> Dict[str, Any]:
    """查询NDR平台告警信息"""
    if not base_url or not api_key:
        return {"error": "NDR平台配置不完整"}

    try:
        url = f"{base_url}/api/v1/alert/search"
        payload = {
            "page": query_params["page"],
            "page_size": query_params["page_size"],
            "start_time": query_params["start_time"],
            "end_time": query_params["end_time"]
        }

        # 资产IP筛选
        if query_params["asset_ip"]:
            payload["ip"] = query_params["asset_ip"]

        # 级别筛选
        if query_params["severity"]:
            payload["severity"] = query_params["severity"]

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
        if not result_data or not result_data.get("list"):
            return {"error": "NDR平台未查询到告警信息"}

        # 解析NDR结果
        parsed_alerts = [_parse_ndr_alert_item(item) for item in result_data["list"]]

        return {
            "platform": "ndr",
            "total": result_data.get("total", 0),
            "page": result_data.get("page", 1),
            "page_size": result_data.get("page_size", 10),
            "alerts": parsed_alerts
        }

    except Exception as e:
        return {"error": f"NDR查询异常: {str(e)}"}


async def _query_corplink_alert(query_params: Dict[str, Any], base_url: str, api_key: str, timeout: int) -> Dict[str, Any]:
    """查询Corplink平台终端安全告警信息"""
    if not base_url or not api_key:
        return {"error": "Corplink平台配置不完整"}

    try:
        # Corplink有三类告警，优先查询防病毒事件
        url = f"{base_url}/open/v1/security/anti_virus/events/list"
        headers = {"Authorization": f"Bearer {api_key}"}
        params = {
            "ip": query_params["asset_ip"],
            "pageSize": query_params["page_size"],
            "page": query_params["page"]
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != 0:
            return {
                "error": f"查询失败: {data.get('message', '未知错误')}"
            }

        result_data = data.get("data", {})
        if not result_data or not result_data.get("items"):
            return {"error": "Corplink平台未查询到告警信息"}

        # 解析Corplink结果
        parsed_alerts = [_parse_corplink_alert_item(item) for item in result_data["items"]]

        return {
            "platform": "corplink",
            "total": result_data.get("total", 0),
            "page": result_data.get("page", 1),
            "page_size": result_data.get("pageSize", 10),
            "alerts": parsed_alerts
        }

    except Exception as e:
        return {"error": f"Corplink查询异常: {str(e)}"}


def _parse_xdr_alert_item(data: Dict[str, Any]) -> Dict[str, Any]:
    """解析XDR告警条目"""
    severity_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
    severity_name_map = {0: "信息", 1: "低危", 2: "中危", 3: "高危", 4: "严重"}

    return {
        "alert_id": data.get("uuId", ""),
        "alert_name": data.get("alertName", ""),
        "description": data.get("description", ""),
        "severity": data.get("severity", 0),
        "severity_code": severity_map.get(data.get("severity", 0), "info"),
        "severity_name": severity_name_map.get(data.get("severity", 0), "未知"),
        "event_type": data.get("eventType", ""),
        "source_ip": data.get("srcIp", ""),
        "destination_ip": data.get("dstIp", ""),
        "host_ip": data.get("hostIp", ""),
        "occur_time": data.get("eventTime", 0) // 1000,  # 转换为秒时间戳
        "alert_url": data.get("alertUrl", ""),
        "risk_tags": data.get("riskTag", []),
        "attack_technique": data.get("attckTechnique", ""),
        "tactic": data.get("attckTactic", ""),
        "deal_status": data.get("dealStatus", 0),
        "data_source": data.get("dataSource", "")
    }


def _parse_ndr_alert_item(data: Dict[str, Any]) -> Dict[str, Any]:
    """解析NDR告警条目"""
    severity_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    severity_name_map = {0: "信息", 1: "低危", 2: "中危", 3: "高危", 4: "严重"}

    severity = data.get("severity", "low")
    severity_level = severity_map.get(severity.lower(), 1) if isinstance(severity, str) else int(severity)

    return {
        "alert_id": data.get("alert_id", data.get("id", "")),
        "alert_name": data.get("alert_name", data.get("title", "")),
        "description": data.get("description", ""),
        "severity": severity_level,
        "severity_code": severity.lower() if isinstance(severity, str) else "low",
        "severity_name": severity_name_map.get(severity_level, "未知"),
        "attack_type": data.get("attack_type", ""),
        "source_ip": data.get("src_ip", ""),
        "destination_ip": data.get("dst_ip", ""),
        "source_port": data.get("src_port", 0),
        "destination_port": data.get("dst_port", 0),
        "protocol": data.get("protocol", ""),
        "occur_time": data.get("occur_time", data.get("timestamp", 0)),
        "risk_tags": data.get("risk_tags", data.get("tags", [])),
        "evidence": data.get("evidence", {}),
        "threat_level": data.get("threat_level", "")
    }


def _parse_corplink_alert_item(data: Dict[str, Any]) -> Dict[str, Any]:
    """解析Corplink告警条目"""
    return {
        "alert_id": data.get("event_id", ""),
        "alert_name": data.get("event_name", ""),
        "description": data.get("description", ""),
        "severity": 3,  # 终端安全告警默认高危
        "severity_code": "high",
        "severity_name": "高危",
        "event_type": "endpoint_security",
        "host_ip": data.get("ip", ""),
        "device_name": data.get("device_name", ""),
        "user_name": data.get("user_name", ""),
        "occur_time": data.get("event_time", 0),
        "risk_tags": ["malware", "endpoint"],
        "file_path": data.get("file_path", ""),
        "virus_name": data.get("virus_name", ""),
        "process_name": data.get("process_name", "")
    }


def _merge_alert_results(platform_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """合并多平台告警信息"""
    merged = {
        "total": 0,
        "alerts": [],
        "source_platforms": [],
        "severity_statistics": {
            "info": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0
        }
    }

    all_alerts = []
    severity_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}

    for platform in ["xdr", "ndr", "corplink"]:
        if platform not in platform_results:
            continue

        result = platform_results[platform]
        if "error" in result:
            continue

        merged["source_platforms"].append(platform)

        # 收集所有告警
        alerts = result.get("alerts", [])
        for alert in alerts:
            alert["source_platform"] = platform
            all_alerts.append(alert)
            # 统计告警级别
            severity_code = alert.get("severity_code", "info")
            if severity_code in severity_counts:
                severity_counts[severity_code] += 1

    # 按时间倒序排序
    all_alerts.sort(key=lambda x: x.get("occur_time", 0), reverse=True)

    merged["alerts"] = all_alerts
    merged["total"] = len(all_alerts)
    merged["severity_statistics"] = severity_counts

    # 如果没有任何有效结果
    if not merged["source_platforms"]:
        return {
            "error": "所有平台均未查询到告警信息",
            "total": 0
        }

    return merged
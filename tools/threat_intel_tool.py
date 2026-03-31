"""攻击源威胁情报查询工具
融合ThreatbookMCP（微步在线）、XDR、NDR三个平台的威胁情报查询接口
优先级：ThreatbookMCP > XDR > NDR，必须优先查询微步在线情报
"""
import os
import httpx
from typing import Optional, Dict, Any, List
import asyncio
from google.adk.tools.tool_context import ToolContext


def _get_config():
    """从环境变量获取工具配置"""
    return {
        "threatbook": {
            "enabled": os.getenv("THREATBOOK_ENABLED", "true").lower() == "true",
            "base_url": os.getenv("THREATBOOK_BASE_URL", "https://api.threatbook.cn/v3"),
            "api_key": os.getenv("THREAT_BOOK_API_KEY", os.getenv("THREATBOOK_API_KEY", "")),
        },
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
    }


async def threat_intel_query(
    ip: Optional[str] = None,
    domain: Optional[str] = None,
    hash: Optional[str] = None,
    platform: str = "all",
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    攻击源威胁情报查询工具
    查询外部攻击源IP/域名/哈希的恶意性判定、威胁标签、攻击历史等情报信息
    优先级：ThreatbookMCP（微步在线，1选必须优先） > XDR > NDR

    Args:
        ip: 要查询的IP地址
        domain: 要查询的域名
        hash: 要查询的文件哈希（MD5/SHA1/SHA256）
        platform: 查询平台选择
            - threatbook: 微步在线（优先）
            - xdr: XDR平台
            - ndr: NDR平台
            - all: 按优先级查询所有平台（默认）
        tool_context: 运行时上下文（可选）

    Returns:
        包含威胁情报的字典，自动合并多平台结果
    """
    config = _get_config()
    timeout = 30

    # ThreatbookMCP（微步在线）平台配置（1选必须优先）
    threatbook_enabled = config["threatbook"]["enabled"]
    threatbook_base_url = config["threatbook"]["base_url"]
    threatbook_api_key = config["threatbook"]["api_key"]

    # XDR平台配置
    xdr_enabled = config["xdr"]["enabled"]
    xdr_base_url = config["xdr"]["base_url"]
    xdr_api_key = config["xdr"]["api_key"]

    # NDR平台配置
    ndr_enabled = config["ndr"]["enabled"]
    ndr_base_url = config["ndr"]["base_url"]
    ndr_api_key = config["ndr"]["api_key"]

    # 确定查询类型和值
    query_type = None
    query_value = None
    if ip:
        query_type = "ip"
        query_value = ip
    elif domain:
        query_type = "domain"
        query_value = domain
    elif hash:
        query_type = "hash"
        query_value = hash
    else:
        return {"error": "必须提供ip、domain、hash中的一个查询参数"}

    platform = platform.lower()

    # 收集需要查询的平台，严格按照优先级顺序：Threatbook > XDR > NDR
    platforms_to_query = []
    if platform == "all":
        if threatbook_enabled:
            platforms_to_query.append("threatbook")
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
    for p in platforms_to_query:
        if p == "threatbook":
            tasks.append(_query_threatbook(query_type, query_value, threatbook_base_url, threatbook_api_key, timeout))
        elif p == "xdr":
            tasks.append(_query_xdr(query_type, query_value, xdr_base_url, xdr_api_key, timeout))
        elif p == "ndr":
            tasks.append(_query_ndr(query_type, query_value, ndr_base_url, ndr_api_key, timeout))

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
    merged_result = _merge_intel_results(platform_results, query_type, query_value)

    return {
        "query_type": query_type,
        "query_value": query_value,
        "platforms_queried": platforms_to_query,
        "platform_results": platform_results,
        "merged_result": merged_result
    }

async def _query_threatbook(query_type: str, query_value: str, base_url: str, api_key: str, timeout: int) -> Dict[str, Any]:
    """查询ThreatbookMCP微步在线威胁情报（优先级最高）"""
    if not base_url or not api_key:
        return {"error": "ThreatbookMCP平台配置不完整"}

    try:
        # 微步接口路径：ip/domain/file
        path_type = "file" if query_type == "hash" else query_type
        url = f"{base_url}/{path_type}/query"
        params = {
            "apikey": api_key,
            "resource": query_value,
            "lang": "zh"
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            result = response.json()

        if result.get("response_code") != 0:
            return {
                "error": f"查询失败: {result.get('verbose_msg', '未知错误')}"
            }

        data = result.get("data", {})
        if not data:
            return {"error": "ThreatbookMCP未查询到情报信息"}

        # 解析微步结果
        if query_type == "ip":
            return _parse_threatbook_ip_result(data)
        elif query_type == "domain":
            return _parse_threatbook_domain_result(data)
        elif query_type == "hash":
            return _parse_threatbook_hash_result(data)

    except Exception as e:
        return {"error": f"ThreatbookMCP查询异常: {str(e)}"}


async def _query_xdr(query_type: str, query_value: str, base_url: str, api_key: str, timeout: int) -> Dict[str, Any]:
    """查询XDR平台威胁情报"""
    if not base_url or not api_key:
        return {"error": "XDR平台配置不完整"}

    try:
        if query_type == "ip":
            # 查询IP威胁情报
            url = f"{base_url}/api/xdr/v1/alerts/attcktechniques"
            params = {"ip": query_value}
        elif query_type == "domain":
            # 查询域名威胁情报
            url = f"{base_url}/api/xdr/v1/threat_intel/domain"
            params = {"domain": query_value}
        elif query_type == "hash":
            # 查询文件哈希威胁情报
            url = f"{base_url}/api/xdr/v1/threat_intel/file"
            params = {"hash": query_value}
        else:
            return {"error": "不支持的查询类型"}

        headers = {"Authorization": f"Bearer {api_key}"}
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != "Success":
            return {"error": f"查询失败: {data.get('message', '未知错误')}"}

        result_data = data.get("data", {})
        if not result_data:
            return {"error": "XDR平台未查询到情报信息"}

        return _parse_xdr_result(result_data, query_type)

    except Exception as e:
        return {"error": f"XDR查询异常: {str(e)}"}


async def _query_ndr(query_type: str, query_value: str, base_url: str, api_key: str, timeout: int) -> Dict[str, Any]:
    """查询NDR平台威胁情报"""
    if not base_url or not api_key:
        return {"error": "NDR平台配置不完整"}

    try:
        if query_type == "ip":
            # 查询IP威胁情报
            url = f"{base_url}/api/v1/host/threat/list"
            payload = {"ip": query_value}
        elif query_type == "domain":
            # 查询域名威胁情报
            url = f"{base_url}/api/v1/domain/threat"
            payload = {"domain": query_value}
        elif query_type == "hash":
            # 查询文件哈希威胁情报
            url = f"{base_url}/api/v1/file/threat"
            payload = {"hash": query_value}
        else:
            return {"error": "不支持的查询类型"}

        params = {
            "api_key": api_key,
            "auth_timestamp": str(int(asyncio.get_event_loop().time())),
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != 0:
            return {"error": f"查询失败: {data.get('message', '未知错误')}"}

        result_data = data.get("data", {})
        if not result_data:
            return {"error": "NDR平台未查询到情报信息"}

        return _parse_ndr_result(result_data, query_type)

    except Exception as e:
        return {"error": f"NDR查询异常: {str(e)}"}


def _parse_threatbook_ip_result(data: Dict[str, Any]) -> Dict[str, Any]:
    """解析微步IP查询结果"""
    basic = data.get("basic", {})
    threat = data.get("threat", {})
    return {
        "platform": "threatbook",
        "confidence": 95,  # 微步情报可信度最高
        "risk_level": threat.get("severity", "safe"),
        "risk_level_name": _get_risk_level_name(threat.get("severity", "safe")),
        "is_malicious": threat.get("is_malicious", False),
        "tags": threat.get("tags", []),
        "judge_reason": threat.get("judge_reason", ""),
        "location": f"{basic.get('country', '')} {basic.get('province', '')} {basic.get('city', '')}".strip(),
        "isp": basic.get("isp", ""),
        "scene": basic.get("scene", ""),  # 场景：IDC/专线/家庭宽带等
        "first_seen": data.get("first_seen", ""),
        "last_seen": data.get("last_seen", ""),
        "update_time": data.get("update_time", "")
    }


def _parse_threatbook_domain_result(data: Dict[str, Any]) -> Dict[str, Any]:
    """解析微步域名查询结果"""
    return {
        "platform": "threatbook",
        "confidence": 95,
        "risk_level": data.get("severity", "safe"),
        "risk_level_name": _get_risk_level_name(data.get("severity", "safe")),
        "is_malicious": data.get("is_malicious", False),
        "tags": data.get("tags", []),
        "judge_reason": data.get("judge_reason", ""),
        "registrar": data.get("registrar", ""),
        "registration_date": data.get("registration_date", ""),
        "expiration_date": data.get("expiration_date", ""),
        "resolution_ips": data.get("resolution_ips", []),
        "update_time": data.get("update_time", "")
    }


def _parse_threatbook_hash_result(data: Dict[str, Any]) -> Dict[str, Any]:
    """解析微步哈希查询结果"""
    return {
        "platform": "threatbook",
        "confidence": 95,
        "risk_level": data.get("severity", "safe"),
        "risk_level_name": _get_risk_level_name(data.get("severity", "safe")),
        "is_malicious": data.get("is_malicious", False),
        "tags": data.get("tags", []),
        "judge_reason": data.get("judge_reason", ""),
        "file_name": data.get("file_name", ""),
        "file_type": data.get("file_type", ""),
        "file_size": data.get("file_size", 0),
        "threat_type": data.get("threat_type", ""),  # 病毒/木马/ ransomware等
        "md5": data.get("md5", ""),
        "sha1": data.get("sha1", ""),
        "sha256": data.get("sha256", ""),
        "update_time": data.get("update_time", "")
    }


def _parse_xdr_result(data: Dict[str, Any], query_type: str) -> Dict[str, Any]:
    """解析XDR平台查询结果"""
    return {
        "platform": "xdr",
        "confidence": 80,
        "risk_level": data.get("risk_level", "safe"),
        "risk_level_name": _get_risk_level_name(data.get("risk_level", "safe")),
        "is_malicious": data.get("is_malicious", False),
        "tags": data.get("tags", data.get("risk_tags", [])),
        "judge_reason": data.get("description", data.get("judge_reason", "")),
        "threat_technique": data.get("attck_technique", ""),
        "tactic": data.get("attck_tactic", ""),
        "related_alerts": data.get("related_alerts_count", 0),
        "update_time": data.get("update_time", "")
    }


def _parse_ndr_result(data: Dict[str, Any], query_type: str) -> Dict[str, Any]:
    """解析NDR平台查询结果"""
    severity = data.get("risk_level", data.get("severity", "safe"))
    return {
        "platform": "ndr",
        "confidence": 75,
        "risk_level": severity,
        "risk_level_name": _get_risk_level_name(severity),
        "is_malicious": severity.lower() in ["malicious", "high_risk", "high", "critical"],
        "tags": data.get("tags", []),
        "source": data.get("source", ""),
        "first_seen": data.get("first_seen", ""),
        "last_seen": data.get("last_seen", ""),
        "attack_count": data.get("attack_count", 0),
        "target_count": data.get("target_count", 0),
        "update_time": data.get("update_time", "")
    }


def _merge_intel_results(platform_results: Dict[str, Dict[str, Any]], query_type: str, query_value: str) -> Dict[str, Any]:
    """合并多平台威胁情报结果，优先级高的平台数据权重更高"""
    merged = {
        "query_type": query_type,
        "query_value": query_value,
        "source_platforms": [],
        "confidence": 0,
        "risk_level": "safe",
        "risk_level_name": "安全",
        "is_malicious": False,
        "tags": [],
        "judge_reason": "",
        "evidence": []
    }

    # 优先级权重：Threatbook 0.6, XDR 0.25, NDR 0.15
    weight_map = {
        "threatbook": 0.6,
        "xdr": 0.25,
        "ndr": 0.15
    }

    # 按优先级顺序处理：Threatbook > XDR > NDR
    priority_order = ["threatbook", "xdr", "ndr"]

    # 风险等级分值
    risk_score_map = {
        "safe": 0,
        "suspicious": 50,
        "malicious": 80,
        "high_risk": 100
    }

    total_weight = 0
    total_risk_score = 0
    final_tags = set()
    evidence = []

    for platform in priority_order:
        if platform not in platform_results:
            continue

        result = platform_results[platform]
        if "error" in result:
            continue

        merged["source_platforms"].append(platform)
        weight = weight_map.get(platform, 0)
        total_weight += weight

        # 计算综合风险得分
        risk_level = result.get("risk_level", "safe")
        risk_score = risk_score_map.get(risk_level, 0)
        total_risk_score += risk_score * weight

        # 合并标签
        tags = result.get("tags", [])
        for tag in tags:
            final_tags.add(tag)

        # 收集证据
        evidence.append({
            "platform": platform,
            "confidence": result.get("confidence", 0),
            "risk_level": result.get("risk_level_name", ""),
            "judge_reason": result.get("judge_reason", "")
        })

        # 高优先级平台的判定作为主要参考
        if platform == "threatbook" and result.get("is_malicious"):
            merged["is_malicious"] = True
            merged["judge_reason"] += f"[微步判定: {result.get('judge_reason', '')}]; "

    # 计算综合可信度
    merged["confidence"] = int(min(total_weight * 100, 100))

    # 计算综合风险等级
    if total_weight > 0:
        average_score = total_risk_score / total_weight
        if average_score >= 80:
            merged["risk_level"] = "high_risk"
        elif average_score >= 60:
            merged["risk_level"] = "malicious"
        elif average_score >= 30:
            merged["risk_level"] = "suspicious"
        else:
            merged["risk_level"] = "safe"
        merged["risk_level_name"] = _get_risk_level_name(merged["risk_level"])

    # 如果没有明确判定，至少有一个平台判定为恶意则标记为恶意
    if not merged["is_malicious"]:
        for platform, result in platform_results.items():
            if "error" not in result and result.get("is_malicious"):
                merged["is_malicious"] = True
                break

    merged["tags"] = list(final_tags)
    merged["evidence"] = evidence

    # 如果没有任何有效结果
    if not merged["source_platforms"]:
        return {
            "query_type": query_type,
            "query_value": query_value,
            "error": "所有平台均未查询到该IOC的威胁情报",
            "confidence": 0
        }

    return merged


def _get_risk_level_name(level: str) -> str:
    """风险等级转中文"""
    level_map = {
        "safe": "安全",
        "low": "低危",
        "suspicious": "可疑",
        "medium": "中危",
        "malicious": "恶意",
        "high": "高危",
        "high_risk": "高风险",
        "critical": "严重"
    }
    return level_map.get(level.lower() if level else "unknown", "未知")

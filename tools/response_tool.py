"""处置操作工具
融合XDR、NDR两个平台的处置操作接口，支持封禁、白名单、状态更新等操作
注意：高风险操作需要人工确认（由Agent通过HITL机制实现）
"""
import os
import httpx
from typing import Optional, Dict, Any, List
import asyncio
from google.adk.tools.tool_context import ToolContext


def _get_config():
    """从环境变量获取工具配置，支持多NDR实例"""
    # NDR多实例配置（集团北、集团南两个数据中心）
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
        "ndr_instances": ndr_instances,  # 多实例字典
        # 内部网段配置，用于安全校验
        "internal_networks": os.getenv("INTERNAL_NETWORKS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(","),
        # 核心业务系统IP列表
        "core_systems": os.getenv("CORE_SYSTEMS", "").split(",") if os.getenv("CORE_SYSTEMS") else [],
    }


def _ip_in_network(ip: str, network: str) -> bool:
    """检查IP是否在网段内"""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        network_obj = ipaddress.ip_network(network.strip(), strict=False)
        return ip_obj in network_obj
    except ValueError:
        return False


def _security_check(action_type: str, target: str, target_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    安全校验
    检查操作是否安全，返回校验结果
    """
    result = {
        "passed": True,
        "reason": "",
        "warnings": [],
        "risk_level": "low"
    }

    # 封禁操作的安全检查
    if action_type in ["block", "aside_block", "linkage_block"]:
        # 优先检查是否为核心业务系统（最高优先级）
        core_systems = config.get("core_systems", [])
        if target in core_systems:
            result["warnings"].append(f"目标 {target} 是核心业务系统")
            result["risk_level"] = "critical"

        # 检查是否为内部网段
        if target_type == "ip" and result["risk_level"] != "critical":
            for network in config.get("internal_networks", []):
                if network and _ip_in_network(target, network.strip()):
                    result["warnings"].append(f"目标IP {target} 属于内部网段 {network}")
                    result["risk_level"] = "high"
                    break

    # 高风险操作标记
    if result["risk_level"] in ["high", "critical"]:
        result["reason"] = f"检测到高风险操作，建议人工确认。警告: {'; '.join(result['warnings'])}"
        # 注意：这里不阻断操作，由Agent层通过HITL机制处理人工确认

    return result


def _generate_ndr_auth_params(api_key: str, api_secret: str) -> Dict[str, str]:
    """生成NDR平台认证参数"""
    import time
    import hmac
    import hashlib
    import base64

    timestamp = str(int(time.time()))
    sign_string = api_key + timestamp
    sign = base64.urlsafe_b64encode(
        hmac.new(api_secret.encode(), sign_string.encode(), hashlib.sha256).digest()
    ).decode()

    return {
        "api_key": api_key,
        "auth_timestamp": timestamp,
        "sign": sign
    }


# ==================== XDR平台操作 ====================

async def _xdr_update_alert_status(
    base_url: str,
    api_key: str,
    alert_ids: List[str],
    deal_status: int,
    comment: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """XDR平台：批量修改安全告警处置状态"""
    try:
        url = f"{base_url}/api/xdr/v1/alerts/dealstatus"
        headers = {"Authorization": f"Bearer {api_key}"}

        payload = {
            "uuIds": alert_ids,
            "dealStatus": deal_status,
            "dealComment": comment or "通过XSOC智能体自动处置"
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != "Success":
            return {"success": False, "error": f"操作失败: {data.get('message', '未知错误')}"}

        return {
            "success": True,
            "platform": "xdr",
            "action": "update_alert_status",
            "total": data.get("data", {}).get("total", 0),
            "succeeded_num": data.get("data", {}).get("succeededNum", 0)
        }

    except Exception as e:
        return {"success": False, "error": f"XDR操作异常: {str(e)}"}


async def _xdr_update_incident_status(
    base_url: str,
    api_key: str,
    incident_ids: List[str],
    deal_status: int,
    comment: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """XDR平台：批量修改安全事件处置状态"""
    try:
        url = f"{base_url}/api/xdr/v1/incidents/dealstatus"
        headers = {"Authorization": f"Bearer {api_key}"}

        # XDR事件处置状态：0-待处置, 10-处置中, 40-已处置, 50-已挂起, 60-接受风险, 70-已遏制
        payload = {
            "uuIds": incident_ids,
            "dealStatus": deal_status,
            "dealComment": comment or "通过XSOC智能体自动处置"
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != "Success":
            return {"success": False, "error": f"操作失败: {data.get('message', '未知错误')}"}

        return {
            "success": True,
            "platform": "xdr",
            "action": "update_incident_status",
            "total": data.get("data", {}).get("total", 0),
            "succeeded_num": data.get("data", {}).get("succeededNum", 0)
        }

    except Exception as e:
        return {"success": False, "error": f"XDR操作异常: {str(e)}"}


async def _xdr_list_dealstatus(
    base_url: str,
    api_key: str,
    target_type: str,
    page: int,
    page_size: int,
    timeout: int
) -> Dict[str, Any]:
    """XDR平台：查询处置状态列表"""
    try:
        if target_type == "alert":
            url = f"{base_url}/api/xdr/v1/alerts/dealstatus/list"
        else:
            url = f"{base_url}/api/xdr/v1/incidents/dealstatus/list"

        headers = {"Authorization": f"Bearer {api_key}"}
        payload = {
            "page": page,
            "pageSize": page_size
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != "Success":
            return {"success": False, "error": f"查询失败: {data.get('message', '未知错误')}"}

        result_data = data.get("data", {})
        return {
            "success": True,
            "platform": "xdr",
            "target_type": target_type,
            "total": result_data.get("total", 0),
            "page": result_data.get("page", page),
            "page_size": result_data.get("pageSize", page_size),
            "items": result_data.get("item", [])
        }

    except Exception as e:
        return {"success": False, "error": f"XDR查询异常: {str(e)}"}


async def _xdr_create_whitelist(
    base_url: str,
    api_key: str,
    name: str,
    rule_list: List[Dict[str, Any]],
    threat_sub_type_ids: List[str],
    host_ips: Optional[List[str]],
    is_host_all: bool,
    time_range: Optional[List[int]],
    is_unlimited: bool,
    reason: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """XDR平台：创建白名单规则"""
    try:
        url = f"{base_url}/api/xdr/v1/whitelists"
        headers = {"Authorization": f"Bearer {api_key}"}

        payload = {
            "name": name,
            "status": "enable",
            "isHostAll": is_host_all,
            "ruleList": rule_list,
            "threatSubTypeIds": threat_sub_type_ids,
            "isUnlimited": 1 if is_unlimited else 0,
            "reason": reason or "通过XSOC智能体创建"
        }

        if not is_host_all and host_ips:
            payload["hostIp"] = host_ips

        if not is_unlimited and time_range:
            payload["timeRange"] = time_range

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != "Success":
            return {"success": False, "error": f"创建失败: {data.get('message', '未知错误')}"}

        return {
            "success": True,
            "platform": "xdr",
            "action": "create_whitelist",
            "name": name
        }

    except Exception as e:
        return {"success": False, "error": f"XDR操作异常: {str(e)}"}


async def _xdr_delete_whitelist(
    base_url: str,
    api_key: str,
    whitelist_ids: List[str],
    timeout: int
) -> Dict[str, Any]:
    """XDR平台：删除白名单规则"""
    try:
        url = f"{base_url}/api/xdr/v1/whitelists"
        headers = {"Authorization": f"Bearer {api_key}"}

        params = {"ids": ",".join(whitelist_ids)}

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.delete(url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != "Success":
            return {"success": False, "error": f"删除失败: {data.get('message', '未知错误')}"}

        return {
            "success": True,
            "platform": "xdr",
            "action": "delete_whitelist",
            "deleted_ids": whitelist_ids
        }

    except Exception as e:
        return {"success": False, "error": f"XDR操作异常: {str(e)}"}


async def _xdr_update_whitelist(
    base_url: str,
    api_key: str,
    whitelist_id: str,
    name: Optional[str],
    rule_list: Optional[List[Dict[str, Any]]],
    timeout: int
) -> Dict[str, Any]:
    """XDR平台：更新白名单规则"""
    try:
        url = f"{base_url}/api/xdr/v1/whitelists/{whitelist_id}"
        headers = {"Authorization": f"Bearer {api_key}"}

        payload = {}
        if name:
            payload["name"] = name
        if rule_list:
            payload["ruleList"] = rule_list

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.put(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != "Success":
            return {"success": False, "error": f"更新失败: {data.get('message', '未知错误')}"}

        return {
            "success": True,
            "platform": "xdr",
            "action": "update_whitelist",
            "whitelist_id": whitelist_id
        }

    except Exception as e:
        return {"success": False, "error": f"XDR操作异常: {str(e)}"}


async def _xdr_update_whitelist_status(
    base_url: str,
    api_key: str,
    whitelist_id: str,
    status: bool,
    timeout: int
) -> Dict[str, Any]:
    """XDR平台：更新白名单启用状态"""
    try:
        url = f"{base_url}/api/xdr/v1/whitelists/{whitelist_id}/status"
        headers = {"Authorization": f"Bearer {api_key}"}

        payload = {"status": "enable" if status else "disable"}

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.put(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != "Success":
            return {"success": False, "error": f"操作失败: {data.get('message', '未知错误')}"}

        return {
            "success": True,
            "platform": "xdr",
            "action": "update_whitelist_status",
            "whitelist_id": whitelist_id,
            "status": status
        }

    except Exception as e:
        return {"success": False, "error": f"XDR操作异常: {str(e)}"}


async def _xdr_list_whitelists(
    base_url: str,
    api_key: str,
    page: int,
    page_size: int,
    keyword: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """XDR平台：查询白名单列表"""
    try:
        url = f"{base_url}/api/xdr/v1/whitelists/list"
        headers = {"Authorization": f"Bearer {api_key}"}

        payload = {
            "page": page,
            "pageSize": page_size,
            "order": "desc",
            "sortKey": "createTime"
        }

        if keyword:
            payload["keyword"] = keyword

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        if data.get("code") != "Success":
            return {"success": False, "error": f"查询失败: {data.get('message', '未知错误')}"}

        result_data = data.get("data", {})
        return {
            "success": True,
            "platform": "xdr",
            "total": result_data.get("total", 0),
            "page": result_data.get("page", page),
            "page_size": result_data.get("pageSize", page_size),
            "items": result_data.get("item", [])
        }

    except Exception as e:
        return {"success": False, "error": f"XDR查询异常: {str(e)}"}


# ==================== NDR平台操作 ====================

async def _ndr_add_linkage_block(
    base_url: str,
    api_key: str,
    api_secret: str,
    ip: str,
    duration: int,
    description: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：添加联动阻断规则"""
    try:
        url = f"{base_url}/api/v1/linkage/block/add"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {
            "ip": ip,
            "duration": duration,
            "description": description or "通过XSOC智能体封禁"
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"操作失败: {data.get('verbose_msg', '未知错误')}"}

        return {
            "success": True,
            "platform": "ndr",
            "action": "linkage_block_add",
            "ip": ip,
            "duration": duration
        }

    except Exception as e:
        return {"success": False, "error": f"NDR操作异常: {str(e)}"}


async def _ndr_delete_linkage_block(
    base_url: str,
    api_key: str,
    api_secret: str,
    ip: str,
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：删除联动阻断规则"""
    try:
        url = f"{base_url}/api/v1/linkage/block/delete"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {"ip": ip}

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"操作失败: {data.get('verbose_msg', '未知错误')}"}

        return {
            "success": True,
            "platform": "ndr",
            "action": "linkage_block_delete",
            "ip": ip
        }

    except Exception as e:
        return {"success": False, "error": f"NDR操作异常: {str(e)}"}


async def _ndr_list_linkage_blocks(
    base_url: str,
    api_key: str,
    api_secret: str,
    page: int,
    page_size: int,
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：查询联动阻断列表"""
    try:
        url = f"{base_url}/api/v1/linkage/block/list"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {
            "page": page,
            "page_size": page_size
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"查询失败: {data.get('verbose_msg', '未知错误')}"}

        result_data = data.get("data", {})
        return {
            "success": True,
            "platform": "ndr",
            "total": result_data.get("total", 0),
            "page": page,
            "page_size": page_size,
            "items": result_data.get("items", [])
        }

    except Exception as e:
        return {"success": False, "error": f"NDR查询异常: {str(e)}"}


async def _ndr_add_aside_block(
    base_url: str,
    api_key: str,
    api_secret: str,
    ip: str,
    duration: int,
    description: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：添加旁路阻断规则"""
    try:
        url = f"{base_url}/api/v1/aside/block/add"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {
            "ip": ip,
            "duration": duration,
            "description": description or "通过XSOC智能体封禁"
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"操作失败: {data.get('verbose_msg', '未知错误')}"}

        return {
            "success": True,
            "platform": "ndr",
            "action": "aside_block_add",
            "ip": ip,
            "duration": duration
        }

    except Exception as e:
        return {"success": False, "error": f"NDR操作异常: {str(e)}"}


async def _ndr_delete_aside_block(
    base_url: str,
    api_key: str,
    api_secret: str,
    ip: str,
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：删除旁路阻断规则"""
    try:
        url = f"{base_url}/api/v1/aside/block/delete"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {"ip": ip}

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"操作失败: {data.get('verbose_msg', '未知错误')}"}

        return {
            "success": True,
            "platform": "ndr",
            "action": "aside_block_delete",
            "ip": ip
        }

    except Exception as e:
        return {"success": False, "error": f"NDR操作异常: {str(e)}"}


async def _ndr_list_aside_blocks(
    base_url: str,
    api_key: str,
    api_secret: str,
    page: int,
    page_size: int,
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：查询旁路阻断列表"""
    try:
        url = f"{base_url}/api/v1/aside/block/list"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {
            "page": page,
            "page_size": page_size
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"查询失败: {data.get('verbose_msg', '未知错误')}"}

        result_data = data.get("data", {})
        return {
            "success": True,
            "platform": "ndr",
            "total": result_data.get("total", 0),
            "page": page,
            "page_size": page_size,
            "items": result_data.get("items", [])
        }

    except Exception as e:
        return {"success": False, "error": f"NDR查询异常: {str(e)}"}


async def _ndr_add_custom_ioc(
    base_url: str,
    api_key: str,
    api_secret: str,
    ioc_type: str,
    ioc_value: str,
    threat_type: str,
    description: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：添加自定义IOC"""
    try:
        url = f"{base_url}/api/v1/custom/ioc/add"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {
            "ioc_type": ioc_type,  # ip/domain/url/hash
            "ioc_value": ioc_value,
            "threat_type": threat_type,
            "description": description or "通过XSOC智能体添加"
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"操作失败: {data.get('verbose_msg', '未知错误')}"}

        return {
            "success": True,
            "platform": "ndr",
            "action": "custom_ioc_add",
            "ioc_type": ioc_type,
            "ioc_value": ioc_value
        }

    except Exception as e:
        return {"success": False, "error": f"NDR操作异常: {str(e)}"}


async def _ndr_delete_custom_ioc(
    base_url: str,
    api_key: str,
    api_secret: str,
    ioc_value: str,
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：删除自定义IOC"""
    try:
        url = f"{base_url}/api/v1/custom/ioc/delete"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {"ioc_value": ioc_value}

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"操作失败: {data.get('verbose_msg', '未知错误')}"}

        return {
            "success": True,
            "platform": "ndr",
            "action": "custom_ioc_delete",
            "ioc_value": ioc_value
        }

    except Exception as e:
        return {"success": False, "error": f"NDR操作异常: {str(e)}"}


async def _ndr_list_custom_iocs(
    base_url: str,
    api_key: str,
    api_secret: str,
    page: int,
    page_size: int,
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：查询自定义IOC列表"""
    try:
        url = f"{base_url}/api/v1/custom/ioc/list"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {
            "page": page,
            "page_size": page_size
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"查询失败: {data.get('verbose_msg', '未知错误')}"}

        result_data = data.get("data", {})
        return {
            "success": True,
            "platform": "ndr",
            "total": result_data.get("total", 0),
            "page": page,
            "page_size": page_size,
            "items": result_data.get("items", [])
        }

    except Exception as e:
        return {"success": False, "error": f"NDR查询异常: {str(e)}"}


async def _ndr_update_alert_status(
    base_url: str,
    api_key: str,
    api_secret: str,
    alert_id: str,
    disposal_status: int,
    disposal_comment: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：更新告警处置状态"""
    try:
        url = f"{base_url}/api/v1/alert/disposal/status/update"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {
            "alert_id": alert_id,
            "disposal_status": disposal_status,  # 3: 已处理
            "disposal_comment": disposal_comment or "通过XSOC智能体处置"
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"操作失败: {data.get('verbose_msg', '未知错误')}"}

        return {
            "success": True,
            "platform": "ndr",
            "action": "update_alert_status",
            "alert_id": alert_id
        }

    except Exception as e:
        return {"success": False, "error": f"NDR操作异常: {str(e)}"}


async def _ndr_add_whitelist(
    base_url: str,
    api_key: str,
    api_secret: str,
    whitelist_type: str,
    value: str,
    description: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：添加白名单（只允许操作白名单，不允许操作资产）"""
    try:
        url = f"{base_url}/api/v1/whitelist/add"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {
            "type": whitelist_type,  # ip/domain/url
            "value": value,
            "description": description or "通过XSOC智能体添加白名单"
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"操作失败: {data.get('verbose_msg', '未知错误')}"}

        return {
            "success": True,
            "platform": "ndr",
            "action": "whitelist_add",
            "type": whitelist_type,
            "value": value
        }

    except Exception as e:
        return {"success": False, "error": f"NDR操作异常: {str(e)}"}


async def _ndr_delete_whitelist(
    base_url: str,
    api_key: str,
    api_secret: str,
    whitelist_id: str,
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：删除白名单"""
    try:
        url = f"{base_url}/api/v1/whitelist/delete"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {"id": whitelist_id}

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"操作失败: {data.get('verbose_msg', '未知错误')}"}

        return {
            "success": True,
            "platform": "ndr",
            "action": "whitelist_delete",
            "whitelist_id": whitelist_id
        }

    except Exception as e:
        return {"success": False, "error": f"NDR操作异常: {str(e)}"}


async def _ndr_list_whitelists(
    base_url: str,
    api_key: str,
    api_secret: str,
    page: int,
    page_size: int,
    timeout: int
) -> Dict[str, Any]:
    """NDR平台：查询白名单列表"""
    try:
        url = f"{base_url}/api/v1/whitelist/list"
        params = _generate_ndr_auth_params(api_key, api_secret)

        payload = {
            "page": page,
            "page_size": page_size
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, params=params)
            response.raise_for_status()
            data = response.json()

        if data.get("response_code", -1) != 0:
            return {"success": False, "error": f"查询失败: {data.get('verbose_msg', '未知错误')}"}

        result_data = data.get("data", {})
        return {
            "success": True,
            "platform": "ndr",
            "total": result_data.get("total", 0),
            "page": page,
            "page_size": page_size,
            "items": result_data.get("items", [])
        }

    except Exception as e:
        return {"success": False, "error": f"NDR查询异常: {str(e)}"}


# ==================== 操作结果验证 ====================

async def _verify_block_result(
    platform: str,
    config: Dict[str, Any],
    target: str,
    timeout: int
) -> bool:
    """验证封禁操作是否生效"""
    try:
        if platform == "ndr":
            # 获取第一个启用的NDR实例
            ndr_instances = config.get("ndr_instances", {})
            ndr_config = next((inst for inst in ndr_instances.values() if inst.get("enabled")), None)
            if not ndr_config:
                return False
            
            # 查询NDR阻断列表，确认目标IP已封禁
            result = await _ndr_list_linkage_blocks(
                ndr_config["base_url"],
                ndr_config["api_key"],
                ndr_config["api_secret"],
                page=1,
                page_size=100,
                timeout=timeout
            )
            if result.get("success"):
                for item in result.get("items", []):
                    if item.get("ip") == target:
                        return True
        return False
    except Exception:
        return False


async def _verify_whitelist_result(
    platform: str,
    config: Dict[str, Any],
    target: str,
    timeout: int
) -> bool:
    """验证白名单操作是否生效"""
    try:
        if platform == "xdr":
            result = await _xdr_list_whitelists(
                config["xdr"]["base_url"],
                config["xdr"]["api_key"],
                page=1,
                page_size=100,
                keyword=target,
                timeout=timeout
            )
            if result.get("success"):
                for item in result.get("items", []):
                    for rule in item.get("ruleList", []):
                        if target in rule.get("view", []):
                            return True
        elif platform == "ndr":
            # 获取第一个启用的NDR实例
            ndr_instances = config.get("ndr_instances", {})
            ndr_config = next((inst for inst in ndr_instances.values() if inst.get("enabled")), None)
            if not ndr_config:
                return False
            
            result = await _ndr_list_whitelists(
                ndr_config["base_url"],
                ndr_config["api_key"],
                ndr_config["api_secret"],
                page=1,
                page_size=100,
                timeout=timeout
            )
            if result.get("success"):
                for item in result.get("items", []):
                    if item.get("value") == target:
                        return True
        return False
    except Exception:
        return False


# ==================== 失败回滚操作 ====================

async def _rollback_block(
    platform: str,
    config: Dict[str, Any],
    target: str,
    timeout: int
) -> Dict[str, Any]:
    """回滚封禁操作"""
    try:
        if platform == "ndr":
            # 获取第一个启用的NDR实例
            ndr_instances = config.get("ndr_instances", {})
            ndr_config = next((inst for inst in ndr_instances.values() if inst.get("enabled")), None)
            if not ndr_config:
                return {"success": False, "error": "没有启用的NDR实例"}
            
            return await _ndr_delete_linkage_block(
                ndr_config["base_url"],
                ndr_config["api_key"],
                ndr_config["api_secret"],
                target,
                timeout
            )
        return {"success": False, "error": f"平台 {platform} 不支持回滚封禁"}
    except Exception as e:
        return {"success": False, "error": f"回滚失败: {str(e)}"}


async def _rollback_whitelist(
    platform: str,
    config: Dict[str, Any],
    target: str,
    whitelist_id: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """回滚白名单操作"""
    try:
        if platform == "xdr" and whitelist_id:
            return await _xdr_delete_whitelist(
                config["xdr"]["base_url"],
                config["xdr"]["api_key"],
                [whitelist_id],
                timeout
            )
        elif platform == "ndr" and whitelist_id:
            # 获取第一个启用的NDR实例
            ndr_instances = config.get("ndr_instances", {})
            ndr_config = next((inst for inst in ndr_instances.values() if inst.get("enabled")), None)
            if not ndr_config:
                return {"success": False, "error": "没有启用的NDR实例"}
            
            return await _ndr_delete_whitelist(
                ndr_config["base_url"],
                ndr_config["api_key"],
                ndr_config["api_secret"],
                whitelist_id,
                timeout
            )
        return {"success": False, "error": f"无法回滚：缺少whitelist_id"}
    except Exception as e:
        return {"success": False, "error": f"回滚失败: {str(e)}"}


# ==================== 主要对外接口 ====================

async def response_action(
    action_type: str,
    target: str,
    target_type: str = "ip",
    duration: int = 3600,
    platform: str = "xdr",
    comment: Optional[str] = None,
    verify_result: bool = True,
    auto_rollback: bool = True,
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    处置操作工具
    执行IP封禁、白名单管理、告警状态更新等处置操作

    Args:
        action_type: 操作类型
            - block: 封禁IP/域名（使用联动阻断）
            - aside_block: 旁路阻断
            - linkage_block: 联动阻断
            - unblock: 解封IP/域名
            - whitelist: 添加白名单
            - remove_whitelist: 移除白名单
            - update_status: 更新告警/事件处置状态
        target: 操作目标
            - 封禁/解封时：IP地址或域名
            - 状态更新时：告警ID或事件ID（多个用逗号分隔）
        target_type: 目标类型
            - ip: IP地址
            - domain: 域名
            - alert: 告警
            - incident: 事件
        duration: 封禁持续时间（秒），默认3600秒（1小时）
        platform: 操作平台
            - xdr: XDR平台（默认）
            - ndr: NDR平台
            - all: 同时操作所有平台
        comment: 操作备注/原因说明
        verify_result: 是否验证操作结果，默认True
        auto_rollback: 操作失败时是否自动回滚，默认True
        tool_context: 运行时上下文（可选）

    Returns:
        包含操作结果的字典
    """
    config = _get_config()
    timeout = 30

    # 安全校验
    security_check = _security_check(action_type, target, target_type, config)
    if not security_check["passed"]:
        return {
            "success": False,
            "error": f"安全校验未通过: {security_check['reason']}",
            "action_type": action_type,
            "target": target
        }

    platform = platform.lower()

    # 收集需要操作的平台和实例
    platforms_to_execute = []  # 格式: (platform, instance_name)
    ndr_instances = config.get("ndr_instances", {})
    
    if platform == "all":
        if config["xdr"]["enabled"]:
            platforms_to_execute.append(("xdr", None))
        # 所有NDR实例
        for instance_name, instance_config in ndr_instances.items():
            if instance_config["enabled"]:
                platforms_to_execute.append(("ndr", instance_name))
    elif platform == "ndr":
        # 所有NDR实例
        for instance_name, instance_config in ndr_instances.items():
            if instance_config["enabled"]:
                platforms_to_execute.append(("ndr", instance_name))
    else:
        platforms_to_execute.append((platform, None))

    if not platforms_to_execute:
        return {"success": False, "error": "没有可用的操作平台，请检查配置"}

    # 执行操作 - 并发执行多NDR实例
    async def execute_on_platform(p: str, instance_name: Optional[str]) -> Dict[str, Any]:
        """在指定平台/实例上执行操作"""
        result = None
        executed_action = None
        
        if p == "xdr":
            if action_type == "update_status":
                target_ids = [t.strip() for t in target.split(",")]
                if target_type == "alert":
                    result = await _xdr_update_alert_status(
                        config["xdr"]["base_url"],
                        config["xdr"]["api_key"],
                        target_ids,
                        3,  # 处置完成
                        comment,
                        timeout
                    )
                elif target_type == "incident":
                    result = await _xdr_update_incident_status(
                        config["xdr"]["base_url"],
                        config["xdr"]["api_key"],
                        target_ids,
                        40,  # 已处置
                        comment,
                        timeout
                    )
            elif action_type == "whitelist":
                rule_type_map = {"ip": "srcIp", "domain": "domain"}
                rule_list = [{
                    "type": rule_type_map.get(target_type, "srcIp"),
                    "mode": "=",
                    "view": [target],
                    "isIgnorecase": False
                }]
                result = await _xdr_create_whitelist(
                    config["xdr"]["base_url"],
                    config["xdr"]["api_key"],
                    name=f"XSOC白名单-{target}",
                    rule_list=rule_list,
                    threat_sub_type_ids=["all"],
                    host_ips=None,
                    is_host_all=True,
                    time_range=None,
                    is_unlimited=True,
                    reason=comment,
                    timeout=timeout
                )
                if result.get("success"):
                    executed_action = ("whitelist", p, target, result.get("whitelist_id"))
            elif action_type == "remove_whitelist":
                result = await _xdr_delete_whitelist(
                    config["xdr"]["base_url"],
                    config["xdr"]["api_key"],
                    [target],
                    timeout
                )
            elif action_type == "block":
                result = {"success": False, "error": "XDR平台暂不支持IP封禁操作，请使用NDR平台"}
        
        elif p == "ndr":
            ndr_config = ndr_instances[instance_name]
            if not ndr_config.get("api_secret"):
                result = {"success": False, "error": f"NDR实例 {instance_name} 缺少api_secret配置"}
            elif action_type in ["block", "linkage_block"]:
                result = await _ndr_add_linkage_block(
                    ndr_config["base_url"],
                    ndr_config["api_key"],
                    ndr_config["api_secret"],
                    target,
                    duration,
                    comment,
                    timeout
                )
                if result.get("success"):
                    executed_action = ("block", f"{p}_{instance_name}", target, None)
            elif action_type == "aside_block":
                result = await _ndr_add_aside_block(
                    ndr_config["base_url"],
                    ndr_config["api_key"],
                    ndr_config["api_secret"],
                    target,
                    duration,
                    comment,
                    timeout
                )
                if result.get("success"):
                    executed_action = ("aside_block", f"{p}_{instance_name}", target, None)
            elif action_type == "unblock":
                result = await _ndr_delete_linkage_block(
                    ndr_config["base_url"],
                    ndr_config["api_key"],
                    ndr_config["api_secret"],
                    target,
                    timeout
                )
            elif action_type == "whitelist":
                result = await _ndr_add_whitelist(
                    ndr_config["base_url"],
                    ndr_config["api_key"],
                    ndr_config["api_secret"],
                    whitelist_type=target_type,
                    value=target,
                    description=comment,
                    timeout=timeout
                )
                if result.get("success"):
                    executed_action = ("whitelist", f"{p}_{instance_name}", target, result.get("whitelist_id"))
            elif action_type == "remove_whitelist":
                result = await _ndr_delete_whitelist(
                    ndr_config["base_url"],
                    ndr_config["api_key"],
                    ndr_config["api_secret"],
                    target,
                    timeout
                )
            elif action_type == "update_status" and target_type == "alert":
                result = await _ndr_update_alert_status(
                    ndr_config["base_url"],
                    ndr_config["api_key"],
                    ndr_config["api_secret"],
                    target,
                    3,  # 已处理
                    comment,
                    timeout
                )
        
        return {
            "platform": f"{p}_{instance_name}" if instance_name else p,
            "result": result,
            "executed_action": executed_action
        }
    
    # 并发执行所有平台/实例
    tasks = [execute_on_platform(p, name) for p, name in platforms_to_execute]
    execution_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # 处理结果
    results = []
    executed_actions = []
    
    for i, exec_result in enumerate(execution_results):
        if isinstance(exec_result, Exception):
            p, name = platforms_to_execute[i]
            key = f"{p}_{name}" if name else p
            results.append({
                "platform": key,
                "result": {"success": False, "error": str(exec_result)}
            })
        else:
            results.append({
                "platform": exec_result["platform"],
                "result": exec_result["result"]
            })
            if exec_result["executed_action"]:
                executed_actions.append(exec_result["executed_action"])

    # 统计成功/失败数量
    success_count = sum(1 for r in results if r["result"].get("success"))

    # 如果存在失败且启用了自动回滚
    rollback_results = []
    if auto_rollback and success_count < len(results):
        for action, p, t, whitelist_id in executed_actions:
            rollback_result = None
            if action in ["block", "aside_block"]:
                rollback_result = await _rollback_block(p, config, t, timeout)
            elif action == "whitelist":
                rollback_result = await _rollback_whitelist(p, config, t, whitelist_id, timeout)
            if rollback_result:
                rollback_results.append({"platform": p, "action": action, "rollback_result": rollback_result})

    # 构建返回结果
    overall_success = success_count == len(platforms_to_execute)

    response = {
        "success": overall_success,
        "action_type": action_type,
        "target": target,
        "target_type": target_type,
        "platforms_executed": platforms_to_execute,
        "platform_results": {r["platform"]: r["result"] for r in results},
        "success_count": success_count,
        "security_check": security_check
    }

    if rollback_results:
        response["rollback_results"] = rollback_results
        response["rollback_triggered"] = True

    # 操作结果验证
    if verify_result and overall_success and action_type in ["block", "linkage_block", "aside_block"]:
        for p in platforms_to_execute:
            verified = await _verify_block_result(p, config, target, timeout)
            response["verification"] = response.get("verification", {})
            response["verification"][p] = verified

    return response


async def query_block_list(
    platform: str = "ndr",
    block_type: str = "linkage",
    page: int = 1,
    page_size: int = 20,
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    查询封禁列表

    Args:
        platform: 查询平台，默认ndr（xdr不支持封禁列表查询）
        block_type: 阻断类型
            - linkage: 联动阻断
            - aside: 旁路阻断
        page: 页码
        page_size: 每页数量
        tool_context: 运行时上下文

    Returns:
        封禁列表
    """
    config = _get_config()
    timeout = 30

    if platform == "xdr":
        return {"success": False, "error": "XDR平台不支持封禁列表查询"}

    # 支持多NDR实例，获取第一个启用的实例
    ndr_instances = config.get("ndr_instances", {})
    ndr_config = next((inst for inst in ndr_instances.values() if inst.get("enabled")), None)
    
    if not ndr_config:
        return {"success": False, "error": "没有启用的NDR实例"}
    
    base_url = ndr_config.get("base_url", "")
    api_key = ndr_config.get("api_key", "")
    api_secret = ndr_config.get("api_secret", "")

    if not base_url or not api_key or not api_secret:
        return {"success": False, "error": "NDR平台配置不完整"}

    if block_type == "aside":
        return await _ndr_list_aside_blocks(base_url, api_key, api_secret, page, page_size, timeout)
    else:
        return await _ndr_list_linkage_blocks(base_url, api_key, api_secret, page, page_size, timeout)


async def query_whitelist_list(
    platform: str = "all",
    page: int = 1,
    page_size: int = 20,
    keyword: Optional[str] = None,
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    查询白名单列表

    Args:
        platform: 查询平台：xdr/ndr/all，默认all
        page: 页码
        page_size: 每页数量
        keyword: 模糊查询关键字
        tool_context: 运行时上下文

    Returns:
        白名单列表
    """
    config = _get_config()
    timeout = 30

    platform = platform.lower()
    platforms_to_query = []  # 格式: (platform, instance_name)
    
    # 获取NDR多实例配置
    ndr_instances = config.get("ndr_instances", {})
    
    if platform == "all":
        if config["xdr"]["enabled"]:
            platforms_to_query.append(("xdr", None))
        # 所有NDR实例
        for instance_name, instance_config in ndr_instances.items():
            if instance_config["enabled"]:
                platforms_to_query.append(("ndr", instance_name))
    elif platform == "ndr":
        # 所有NDR实例
        for instance_name, instance_config in ndr_instances.items():
            if instance_config["enabled"]:
                platforms_to_query.append(("ndr", instance_name))
    else:
        platforms_to_query.append((platform, None))

    if not platforms_to_query:
        return {"success": False, "error": "没有可用的查询平台"}

    results = {}
    for p, instance_name in platforms_to_query:
        key = f"{p}_{instance_name}" if instance_name else p
        if p == "xdr":
            results[key] = await _xdr_list_whitelists(
                config["xdr"]["base_url"],
                config["xdr"]["api_key"],
                page,
                page_size,
                keyword,
                timeout
            )
        elif p == "ndr":
            ndr_config = ndr_instances[instance_name]
            results[key] = await _ndr_list_whitelists(
                ndr_config["base_url"],
                ndr_config["api_key"],
                ndr_config["api_secret"],
                page,
                page_size,
                timeout
            )

    return {
        "success": True,
        "platforms_queried": platforms_to_query,
        "platform_results": results
    }


async def query_dealstatus_list(
    platform: str = "xdr",
    target_type: str = "alert",
    page: int = 1,
    page_size: int = 20,
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    查询处置状态列表

    Args:
        platform: 查询平台，默认xdr
        target_type: 目标类型：alert/incident
        page: 页码
        page_size: 每页数量
        tool_context: 运行时上下文

    Returns:
        处置状态列表
    """
    config = _get_config()
    timeout = 30

    if platform == "xdr":
        return await _xdr_list_dealstatus(
            config["xdr"]["base_url"],
            config["xdr"]["api_key"],
            target_type,
            page,
            page_size,
            timeout
        )
    else:
        return {"success": False, "error": f"平台 {platform} 暂不支持处置状态列表查询"}


async def query_custom_ioc_list(
    page: int = 1,
    page_size: int = 20,
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    查询NDR平台自定义IOC列表

    Args:
        page: 页码
        page_size: 每页数量
        tool_context: 运行时上下文

    Returns:
        自定义IOC列表
    """
    config = _get_config()
    timeout = 30

    # 支持多NDR实例，获取第一个启用的实例
    ndr_instances = config.get("ndr_instances", {})
    ndr_config = next((inst for inst in ndr_instances.values() if inst.get("enabled")), None)
    
    if not ndr_config:
        return {"success": False, "error": "没有启用的NDR实例"}

    return await _ndr_list_custom_iocs(
        ndr_config["base_url"],
        ndr_config["api_key"],
        ndr_config["api_secret"],
        page,
        page_size,
        timeout
    )
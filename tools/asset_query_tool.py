"""资产信息查询工具
融合CAASM、Corplink、XDR、NDR四个平台的资产查询接口，支持多平台结果合并
优先级：CAASM > Corplink > XDR > NDR
"""
from veadk import BaseTool, tool_param
from veadk.config import get_config
import httpx
from typing import Optional, Dict, Any, List
import asyncio


class AssetQueryTool(BaseTool):
    """
    资产信息查询工具
    查询服务器/办公终端资产的基础信息、配置信息、风险信息等，支持多平台数据融合
    优先级：CAASM(云盘资产/服务器) > Corplink(办公终端) > XDR > NDR
    """
    name = "asset_query"
    display_name = "资产信息查询"
    description = "查询内部资产信息，支持服务器、办公终端、网络设备等资产的基础信息、风险信息查询，融合多平台数据"

    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.timeout = 30

        # CAASM平台配置
        self.caasm_config = self.config.tools.get("caasm", {})
        self.caasm_enabled = self.caasm_config.get("enabled", True)
        self.caasm_base_url = self.caasm_config.get("base_url", "")
        self.caasm_api_key = self.caasm_config.get("api_key", "")

        # Corplink平台配置
        self.corplink_config = self.config.tools.get("corplink", {})
        self.corplink_enabled = self.corplink_config.get("enabled", True)
        self.corplink_base_url = self.corplink_config.get("base_url", "")
        self.corplink_api_key = self.corplink_config.get("api_key", "")

        # XDR平台配置
        self.xdr_config = self.config.tools.get("xdr", {})
        self.xdr_enabled = self.xdr_config.get("enabled", True)
        self.xdr_base_url = self.xdr_config.get("base_url", "")
        self.xdr_api_key = self.xdr_config.get("api_key", "")

        # NDR平台配置
        self.ndr_config = self.config.tools.get("ndr", {})
        self.ndr_enabled = self.ndr_config.get("enabled", True)
        self.ndr_base_url = self.ndr_config.get("base_url", "")
        self.ndr_api_key = self.ndr_config.get("api_key", "")

    @tool_param(description="要查询的资产IP地址", required=True)
    def asset_ip(self, value: str) -> str:
        return value

    @tool_param(description="查询平台选择：caasm/corplink/xdr/ndr/all，默认all（按优先级查询）", required=False)
    def platform(self, value: str = "all") -> str:
        return value.lower()

    async def run(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """工具执行入口"""
        asset_ip = params["asset_ip"]
        platform = params.get("platform", "all")

        self.logger.info(f"开始查询资产信息: IP={asset_ip}, 平台={platform}")

        # 收集需要查询的平台
        platforms_to_query = []
        if platform == "all":
            # 按优先级顺序添加
            if self.caasm_enabled:
                platforms_to_query.append("caasm")
            if self.corplink_enabled:
                platforms_to_query.append("corplink")
            if self.xdr_enabled:
                platforms_to_query.append("xdr")
            if self.ndr_enabled:
                platforms_to_query.append("ndr")
        else:
            platforms_to_query = [platform]

        if not platforms_to_query:
            return {"error": "没有可用的查询平台，请检查配置"}

        # 并发查询所有平台
        tasks = []
        for p in platforms_to_query:
            if p == "caasm":
                tasks.append(self._query_caasm(asset_ip))
            elif p == "corplink":
                tasks.append(self._query_corplink(asset_ip))
            elif p == "xdr":
                tasks.append(self._query_xdr(asset_ip))
            elif p == "ndr":
                tasks.append(self._query_ndr(asset_ip))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理查询结果
        platform_results = {}
        for i, p in enumerate(platforms_to_query):
            result = results[i]
            if isinstance(result, Exception):
                self.logger.error(f"{p}平台查询异常: {str(result)}")
                platform_results[p] = {"error": str(result)}
            else:
                platform_results[p] = result

        # 合并结果
        merged_result = self._merge_asset_results(platform_results, asset_ip)

        return {
            "asset_ip": asset_ip,
            "platforms_queried": platforms_to_query,
            "platform_results": platform_results,
            "merged_result": merged_result
        }

    async def _query_caasm(self, asset_ip: str) -> Dict[str, Any]:
        """查询CAASM平台资产信息（云盘资产和Fobrain资产）"""
        if not self.caasm_base_url or not self.caasm_api_key:
            return {"error": "CAASM平台配置不完整"}

        try:
            # 1. 查询云盘资产
            cloud_asset = {}
            try:
                url = f"{self.caasm_base_url}/cloud/asset/query"
                params = {"ip": asset_ip}
                headers = {"Authorization": f"Bearer {self.caasm_api_key}"}

                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(url, params=params, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("code") == "Success":
                            cloud_asset = data.get("data", {})
            except Exception as e:
                self.logger.warning(f"CAASM云盘资产查询失败: {str(e)}")

            # 2. 查询Fobrain资产
            fobrain_asset = {}
            try:
                url = f"{self.caasm_base_url}/fobrain/asset/list"
                payload = {"hostIp": [asset_ip]}
                headers = {"Authorization": f"Bearer {self.caasm_api_key}"}

                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(url, json=payload, headers=headers)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("code") == "Success" and data.get("data", {}).get("item"):
                            fobrain_asset = data["data"]["item"][0]
            except Exception as e:
                self.logger.warning(f"CAASM Fobrain资产查询失败: {str(e)}")

            # 合并CAASM平台结果
            caasm_result = {**cloud_asset, **fobrain_asset}

            if not caasm_result:
                return {"error": "CAASM平台未查询到资产信息"}

            return self._parse_caasm_result(caasm_result)

        except Exception as e:
            return {"error": f"CAASM查询异常: {str(e)}"}

    async def _query_corplink(self, asset_ip: str) -> Dict[str, Any]:
        """查询Corplink平台资产信息（办公终端）"""
        if not self.corplink_base_url or not self.corplink_api_key:
            return {"error": "Corplink平台配置不完整"}

        try:
            url = f"{self.corplink_base_url}/open/v1/device/search"
            params = {"ip": asset_ip, "pageSize": 1}
            headers = {"Authorization": f"Bearer {self.corplink_api_key}"}

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()

                if data.get("code") != 0:
                    return {"error": f"查询失败: {data.get('message', '未知错误')}"}

                items = data.get("data", {}).get("items", [])
                if not items:
                    return {"error": "Corplink平台未查询到资产信息"}

                return self._parse_corplink_result(items[0])

        except Exception as e:
            return {"error": f"Corplink查询异常: {str(e)}"}

    async def _query_xdr(self, asset_ip: str) -> Dict[str, Any]:
        """查询XDR平台资产信息（风险资产）"""
        if not self.xdr_base_url or not self.xdr_api_key:
            return {"error": "XDR平台配置不完整"}

        try:
            url = f"{self.xdr_base_url}/api/xdr/v1/riskassets/list"
            payload = {
                "hostBranchIds": [],
                "page": 1,
                "pageSize": 100
            }
            headers = {"Authorization": f"Bearer {self.xdr_api_key}"}

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()

                if data.get("code") != "Success":
                    return {"error": f"查询失败: {data.get('message', '未知错误')}"}

                items = data.get("data", {}).get("item", [])
                # 查找匹配IP的资产
                matched_asset = next((item for item in items if item.get("hostIp") == asset_ip), None)

                if not matched_asset:
                    return {"error": "XDR平台未查询到资产信息"}

                return self._parse_xdr_result(matched_asset)

        except Exception as e:
            return {"error": f"XDR查询异常: {str(e)}"}

    async def _query_ndr(self, asset_ip: str) -> Dict[str, Any]:
        """查询NDR平台资产信息"""
        if not self.ndr_base_url or not self.ndr_api_key:
            return {"error": "NDR平台配置不完整"}

        try:
            url = f"{self.ndr_base_url}/api/v1/asset/list"
            payload = {
                "ip": asset_ip,
                "page": 1,
                "pageSize": 10
            }
            params = {
                "api_key": self.ndr_api_key,
                "auth_timestamp": str(int(asyncio.get_event_loop().time())),
                # 签名计算需要secret，后续补充
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload, params=params)
                response.raise_for_status()
                data = response.json()

                if data.get("code") != 0:
                    return {"error": f"查询失败: {data.get('message', '未知错误')}"}

                items = data.get("data", {}).get("list", [])
                if not items:
                    return {"error": "NDR平台未查询到资产信息"}

                return self._parse_ndr_result(items[0])

        except Exception as e:
            return {"error": f"NDR查询异常: {str(e)}"}

    def _parse_caasm_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析CAASM平台查询结果"""
        return {
            "platform": "caasm",
            "asset_type": "server",  # CAASM主要是服务器资产
            "hostname": data.get("hostName", data.get("asset_name", "")),
            "ip": data.get("hostIp", data.get("ip", "")),
            "os": data.get("os", ""),
            "os_version": data.get("osVersion", ""),
            "department": data.get("department", ""),
            "owner": data.get("owner", data.get("user_name", "")),
            "owner_email": data.get("email", ""),
            "location": data.get("location", ""),
            "asset_status": data.get("status", ""),
            "service_list": data.get("services", []),
            "open_ports": data.get("openPorts", []),
            "risk_level": data.get("riskLevel", data.get("severity", "")),
            "risk_tags": data.get("riskTag", []),
            "vulnerability_count": data.get("vulnCount", 0),
            "last_seen": data.get("lastSeen", ""),
            "asset_create_time": data.get("createTime", "")
        }

    def _parse_corplink_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析Corplink平台查询结果"""
        return {
            "platform": "corplink",
            "asset_type": "endpoint",  # Corplink主要是办公终端
            "hostname": data.get("deviceName", ""),
            "ip": data.get("ip", ""),
            "mac": data.get("mac", ""),
            "os": data.get("os", ""),
            "os_version": data.get("osVersion", ""),
            "department": data.get("departmentName", ""),
            "owner": data.get("userName", ""),
            "owner_email": data.get("userEmail", ""),
            "location": data.get("location", ""),
            "device_type": data.get("deviceType", ""),
            "last_online_time": data.get("lastOnlineTime", ""),
            "antivirus_status": data.get("antiVirusStatus", ""),
            "baseline_compliance": data.get("baselineCompliance", "")
        }

    def _parse_xdr_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析XDR平台查询结果"""
        severity_map = {1: "低危", 2: "中危", 3: "高危", 4: "严重"}
        return {
            "platform": "xdr",
            "asset_type": "server",
            "hostname": data.get("hostName", ""),
            "ip": data.get("hostIp", ""),
            "asset_id": data.get("hostAssetId", ""),
            "risk_level": severity_map.get(data.get("severity", 1), "低危"),
            "risk_tags": data.get("riskTag", []),
            "total_vulnerability_count": data.get("totalVulNumber", 0),
            "high_risk_vulnerability_count": data.get("highlyExploitableVulNumber", 0),
            "weak_password_count": data.get("weakPasswordNumber", 0),
            "incident_count": data.get("incidentNumber", 0),
            "branch_name": data.get("branchName", ""),
            "business_groups": data.get("hostGroups", []),
            "last_detect_time": data.get("detectTime", ""),
            "last_seen": data.get("lastSeen", "")
        }

    def _parse_ndr_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析NDR平台查询结果"""
        return {
            "platform": "ndr",
            "asset_type": "network",
            "hostname": data.get("assetName", data.get("hostName", "")),
            "ip": data.get("ip", data.get("hostIp", "")),
            "asset_type": data.get("assetType", ""),
            "location": data.get("location", ""),
            "service_list": data.get("services", []),
            "open_ports": data.get("ports", []),
            "risk_level": data.get("riskLevel", ""),
            "risk_tags": data.get("riskTags", []),
            "threat_count": data.get("threatCount", 0),
            "first_seen": data.get("firstSeen", ""),
            "last_seen": data.get("lastSeen", "")
        }

    def _merge_asset_results(self, platform_results: Dict[str, Dict[str, Any]], asset_ip: str) -> Dict[str, Any]:
        """合并多平台资产信息，优先级高的平台数据覆盖优先级低的"""
        merged = {
            "asset_ip": asset_ip,
            "source_platforms": [],
            "confidence": 0
        }

        # 按优先级顺序合并：CAASM > Corplink > XDR > NDR
        priority_order = ["caasm", "corplink", "xdr", "ndr"]

        for platform in priority_order:
            if platform not in platform_results:
                continue

            result = platform_results[platform]
            if "error" in result:
                continue

            merged["source_platforms"].append(platform)
            merged["confidence"] += 25  # 每有一个平台数据，可信度+25%

            # 合并字段，优先级高的不会被低的覆盖
            for key, value in result.items():
                if key not in merged:
                    merged[key] = value
                elif isinstance(merged[key], list) and isinstance(value, list):
                    # 列表合并去重
                    merged[key] = list(set(merged[key] + value))
                elif isinstance(merged[key], dict) and isinstance(value, dict):
                    # 字典合并
                    merged[key] = {**value, **merged[key]}

        # 如果没有任何有效结果
        if not merged["source_platforms"]:
            return {
                "asset_ip": asset_ip,
                "error": "所有平台均未查询到该资产信息",
                "confidence": 0
            }

        return merged

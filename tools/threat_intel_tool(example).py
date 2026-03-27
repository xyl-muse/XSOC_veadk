"""微步在线威胁情报查询工具"""
from veadk import BaseTool, tool_param
from veadk.config import get_config
import httpx
from typing import Optional, Dict, Any


class ThreatIntelQueryTool(BaseTool):
    """
    微步在线威胁情报查询工具
    支持查询IP、域名、哈希的威胁属性、风险等级、标签等信息
    """
    name = "threat_intel_query"
    display_name = "威胁情报查询"
    description = "查询微步在线威胁情报，支持IP、域名、文件哈希的威胁属性查询，用于判断IOC的恶意性"

    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.api_key = self.config.tools.threat_intel.api_key
        self.base_url = self.config.tools.threat_intel.base_url
        self.timeout = 30

    @tool_param(description="要查询的IP地址", required=False)
    def ip(self, value: str) -> str:
        return value

    @tool_param(description="要查询的域名", required=False)
    def domain(self, value: str) -> str:
        return value

    @tool_param(description="要查询的文件哈希（MD5/SHA1/SHA256）", required=False)
    def hash(self, value: str) -> str:
        return value

    async def run(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """工具执行入口"""
        if not self.api_key:
            return {"error": "微步威胁情报API密钥未配置"}

        # 确定查询类型
        query_type = None
        query_value = None
        if "ip" in params and params["ip"]:
            query_type = "ip"
            query_value = params["ip"]
        elif "domain" in params and params["domain"]:
            query_type = "domain"
            query_value = params["domain"]
        elif "hash" in params and params["hash"]:
            query_type = "file"
            query_value = params["hash"]
        else:
            return {"error": "必须提供ip、domain、hash中的一个查询参数"}

        try:
            # 调用微步API
            url = f"{self.base_url}/{query_type}/query"
            params = {
                "apikey": self.api_key,
                "resource": query_value,
                "lang": "zh"
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, params=params)
                response.raise_for_status()
                result = response.json()

            if result.get("response_code") != 0:
                return {
                    "error": f"查询失败: {result.get('verbose_msg', '未知错误')}",
                    "query_type": query_type,
                    "query_value": query_value
                }

            # 解析结果，返回结构化数据
            data = result.get("data", {})
            if query_type == "ip":
                return self._parse_ip_result(query_value, data)
            elif query_type == "domain":
                return self._parse_domain_result(query_value, data)
            elif query_type == "file":
                return self._parse_hash_result(query_value, data)

        except Exception as e:
            self.logger.error(f"威胁情报查询失败: {str(e)}")
            return {
                "error": f"查询异常: {str(e)}",
                "query_type": query_type,
                "query_value": query_value
            }

    def _parse_ip_result(self, ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析IP查询结果"""
        basic = data.get("basic", {})
        threat = data.get("threat", {})
        return {
            "query_type": "ip",
            "query_value": ip,
            "risk_level": threat.get("severity", "safe"),
            "risk_level_name": self._get_risk_level_name(threat.get("severity", "safe")),
            "is_malicious": threat.get("is_malicious", False),
            "tags": threat.get("tags", []),
            "judge_reason": threat.get("judge_reason", ""),
            "location": f"{basic.get('country', '')} {basic.get('province', '')} {basic.get('city', '')}",
            "isp": basic.get("isp", ""),
            "scene": basic.get("scene", ""),
            "update_time": data.get("update_time", "")
        }

    def _parse_domain_result(self, domain: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析域名查询结果"""
        return {
            "query_type": "domain",
            "query_value": domain,
            "risk_level": data.get("severity", "safe"),
            "risk_level_name": self._get_risk_level_name(data.get("severity", "safe")),
            "is_malicious": data.get("is_malicious", False),
            "tags": data.get("tags", []),
            "registrar": data.get("registrar", ""),
            "registration_date": data.get("registration_date", ""),
            "expiration_date": data.get("expiration_date", ""),
            "update_time": data.get("update_time", "")
        }

    def _parse_hash_result(self, hash_val: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析哈希查询结果"""
        return {
            "query_type": "hash",
            "query_value": hash_val,
            "risk_level": data.get("severity", "safe"),
            "risk_level_name": self._get_risk_level_name(data.get("severity", "safe")),
            "is_malicious": data.get("is_malicious", False),
            "tags": data.get("tags", []),
            "file_name": data.get("file_name", ""),
            "file_type": data.get("file_type", ""),
            "file_size": data.get("file_size", 0),
            "threat_type": data.get("threat_type", ""),
            "update_time": data.get("update_time", "")
        }

    @staticmethod
    def _get_risk_level_name(level: str) -> str:
        """风险等级转中文"""
        level_map = {
            "safe": "安全",
            "suspicious": "可疑",
            "malicious": "恶意",
            "high_risk": "高风险"
        }
        return level_map.get(level, "未知")

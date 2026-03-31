"""攻击源威胁情报查询工具单元测试"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from tools.threat_intel_tool import threat_intel_query, _merge_intel_results, _get_risk_level_name


class TestThreatIntelQueryTool:
    """攻击源威胁情报查询工具测试类"""

    @pytest.mark.asyncio
    @patch('tools.threat_intel_tool._get_config')
    @patch('tools.threat_intel_tool._query_threatbook')
    @patch('tools.threat_intel_tool._query_xdr')
    async def test_threat_intel_threatbook_priority(self, mock_xdr, mock_threatbook, mock_get_config):
        """测试Threatbook平台优先查询"""
        # 模拟配置
        mock_get_config.return_value = {
            "threatbook": {
                "enabled": True,
                "base_url": "https://api.threatbook.cn/v3",
                "api_key": "test-threatbook-key"
            },
            "xdr": {
                "enabled": True,
                "base_url": "https://xdr.example.com",
                "api_key": "test-xdr-key"
            },
            "ndr": {"enabled": False, "base_url": "", "api_key": ""}
        }

        # 模拟返回结果
        mock_threatbook.return_value = {
            "platform": "threatbook",
            "confidence": 95,
            "risk_level": "malicious",
            "risk_level_name": "恶意",
            "is_malicious": True,
            "tags": ["Web攻击", "暴力破解"],
            "judge_reason": "多次发起攻击"
        }
        mock_xdr.return_value = {
            "platform": "xdr",
            "confidence": 80,
            "risk_level": "high_risk",
            "is_malicious": True,
            "tags": ["僵尸网络"]
        }

        result = await threat_intel_query(ip="1.2.3.4")

        assert result["query_value"] == "1.2.3.4"
        assert result["query_type"] == "ip"
        assert "threatbook" in result["platforms_queried"]
        assert "xdr" in result["platforms_queried"]
        assert result["merged_result"]["is_malicious"] is True
        assert "微步判定" in result["merged_result"]["judge_reason"]  # 微步优先级最高
        mock_threatbook.assert_called_once()
        mock_xdr.assert_called_once()

    @pytest.mark.asyncio
    @patch('tools.threat_intel_tool._get_config')
    @patch('tools.threat_intel_tool._query_threatbook')
    async def test_threat_intel_specific_platform(self, mock_threatbook, mock_get_config):
        """测试指定平台查询"""
        mock_get_config.return_value = {
            "threatbook": {
                "enabled": True,
                "base_url": "https://api.threatbook.cn/v3",
                "api_key": "test-threatbook-key"
            },
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "ndr": {"enabled": False, "base_url": "", "api_key": ""}
        }

        mock_threatbook.return_value = {
            "platform": "threatbook",
            "risk_level": "safe",
            "is_malicious": False,
            "tags": []
        }

        result = await threat_intel_query(ip="1.1.1.1", platform="threatbook")

        assert result["platforms_queried"] == ["threatbook"]
        assert result["merged_result"]["risk_level"] == "safe"
        mock_threatbook.assert_called_once()

    def test_merge_intel_results_all_malicious(self):
        """测试所有平台都返回恶意的结果合并"""
        platform_results = {
            "threatbook": {
                "platform": "threatbook",
                "confidence": 95,
                "risk_level": "malicious",
                "risk_level_name": "恶意",
                "is_malicious": True,
                "tags": ["Web攻击", "暴力破解"],
                "judge_reason": "多次发起攻击"
            },
            "xdr": {
                "platform": "xdr",
                "confidence": 80,
                "risk_level": "high_risk",
                "risk_level_name": "高风险",
                "is_malicious": True,
                "tags": ["暴力破解", "僵尸网络"],
                "judge_reason": "关联多起攻击事件"
            },
            "ndr": {
                "platform": "ndr",
                "confidence": 75,
                "risk_level": "malicious",
                "risk_level_name": "恶意",
                "is_malicious": True,
                "tags": ["扫描"],
                "judge_reason": "持续端口扫描"
            }
        }

        merged = _merge_intel_results(platform_results, "ip", "1.2.3.4")

        assert merged["query_value"] == "1.2.3.4"
        assert merged["source_platforms"] == ["threatbook", "xdr", "ndr"]
        assert merged["confidence"] == 100  # 三个平台加权0.6+0.25+0.15=1.0
        assert merged["is_malicious"] is True
        assert merged["risk_level"] == "high_risk"  # 综合得分最高级
        assert merged["risk_level_name"] == "高风险"
        # 标签合并去重
        assert set(merged["tags"]) == {"Web攻击", "暴力破解", "僵尸网络", "扫描"}
        assert len(merged["evidence"]) == 3

    def test_merge_intel_results_mixed(self):
        """测试不同平台判定结果不一致的合并逻辑"""
        platform_results = {
            "threatbook": {
                "platform": "threatbook",
                "confidence": 95,
                "risk_level": "suspicious",
                "risk_level_name": "可疑",
                "is_malicious": False,
                "tags": ["代理"],
                "judge_reason": "属于公开代理IP"
            },
            "xdr": {
                "platform": "xdr",
                "confidence": 80,
                "risk_level": "malicious",
                "risk_level_name": "恶意",
                "is_malicious": True,
                "tags": ["攻击"],
                "judge_reason": "有攻击记录"
            }
        }

        merged = _merge_intel_results(platform_results, "ip", "1.2.3.4")

        # 只要有一个平台判定为恶意，最终标记为恶意
        assert merged["is_malicious"] is True
        assert merged["risk_level"] == "suspicious"  # 加权平均得分在可疑区间
        assert merged["confidence"] == 85  # 0.6 + 0.25 = 0.85 -> 85%
        assert set(merged["tags"]) == {"代理", "攻击"}

    def test_merge_intel_results_no_data(self):
        """测试所有平台都没有数据的情况"""
        platform_results = {
            "threatbook": {"error": "查询失败"},
            "xdr": {"error": "接口超时"},
            "ndr": {"error": "未查询到数据"}
        }

        merged = _merge_intel_results(platform_results, "ip", "1.2.3.4")

        assert "error" in merged
        assert merged["confidence"] == 0

    def test_risk_level_name_conversion(self):
        """测试风险等级转换"""
        assert _get_risk_level_name("safe") == "安全"
        assert _get_risk_level_name("suspicious") == "可疑"
        assert _get_risk_level_name("malicious") == "恶意"
        assert _get_risk_level_name("high_risk") == "高风险"
        assert _get_risk_level_name("critical") == "严重"
        assert _get_risk_level_name("unknown") == "未知"

    @pytest.mark.asyncio
    @patch('tools.threat_intel_tool._get_config')
    async def test_threat_intel_missing_query_param(self, mock_get_config):
        """测试缺少查询参数的情况"""
        mock_get_config.return_value = {
            "threatbook": {"enabled": False, "base_url": "", "api_key": ""},
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "ndr": {"enabled": False, "base_url": "", "api_key": ""}
        }

        result = await threat_intel_query()

        assert "error" in result
        assert "必须提供ip、domain、hash中的一个查询参数" in result["error"]
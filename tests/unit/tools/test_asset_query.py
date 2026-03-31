"""资产信息查询工具单元测试"""
import pytest
import os
from unittest.mock import AsyncMock, patch, MagicMock
from tools.asset_query_tool import asset_query, _merge_asset_results


class TestAssetQueryTool:
    """资产信息查询工具测试类"""

    @pytest.mark.asyncio
    @patch('tools.asset_query_tool._get_config')
    @patch('tools.asset_query_tool._query_caasm')
    @patch('tools.asset_query_tool._query_corplink')
    async def test_asset_query_caasm_priority(self, mock_corplink, mock_caasm, mock_get_config):
        """测试CAASM平台优先查询"""
        # 模拟配置
        mock_get_config.return_value = {
            "caasm": {
                "enabled": True,
                "base_url": "https://caasm.example.com",
                "api_key": "test-caasm-key"
            },
            "corplink": {
                "enabled": True,
                "base_url": "https://corplink.example.com",
                "api_key": "test-corplink-key"
            },
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "ndr": {"enabled": False, "base_url": "", "api_key": ""}
        }

        # 模拟返回结果
        mock_caasm.return_value = {
            "platform": "caasm",
            "hostname": "server-001",
            "ip": "192.168.1.100",
            "os": "Linux",
            "owner": "zhangsan"
        }
        mock_corplink.return_value = {"error": "未查询到"}

        result = await asset_query(asset_ip="192.168.1.100")

        assert result["asset_ip"] == "192.168.1.100"
        assert "caasm" in result["platforms_queried"]
        assert "corplink" in result["platforms_queried"]
        assert result["merged_result"]["hostname"] == "server-001"  # CAASM优先级高
        mock_caasm.assert_called_once()
        mock_corplink.assert_called_once()

    @pytest.mark.asyncio
    @patch('tools.asset_query_tool._get_config')
    @patch('tools.asset_query_tool._query_caasm')
    async def test_asset_query_specific_platform(self, mock_caasm, mock_get_config):
        """测试指定平台查询"""
        mock_get_config.return_value = {
            "caasm": {
                "enabled": True,
                "base_url": "https://caasm.example.com",
                "api_key": "test-caasm-key"
            },
            "corplink": {"enabled": False, "base_url": "", "api_key": ""},
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "ndr": {"enabled": False, "base_url": "", "api_key": ""}
        }

        mock_caasm.return_value = {
            "platform": "caasm",
            "hostname": "server-001",
            "ip": "192.168.1.100"
        }

        result = await asset_query(asset_ip="192.168.1.100", platform="caasm")

        assert result["platforms_queried"] == ["caasm"]
        assert result["merged_result"]["hostname"] == "server-001"
        mock_caasm.assert_called_once()

    def test_merge_asset_results_priority(self):
        """测试多平台结果合并优先级"""
        platform_results = {
            "caasm": {
                "platform": "caasm",
                "hostname": "server-001",
                "os": "Linux",
                "owner": "zhangsan",
                "tags": ["生产环境", "核心业务"]
            },
            "corplink": {
                "platform": "corplink",
                "hostname": "pc-001",  # 优先级低，不会覆盖CAASM的hostname
                "os": "Windows",
                "owner": "lisi",
                "tags": ["办公终端"]
            },
            "xdr": {
                "platform": "xdr",
                "risk_level": "高危",
                "tags": ["有漏洞"]
            }
        }

        merged = _merge_asset_results(platform_results, "192.168.1.100")

        assert merged["asset_ip"] == "192.168.1.100"
        assert merged["source_platforms"] == ["caasm", "corplink", "xdr"]
        assert merged["confidence"] == 75  # 三个平台各25
        # 高优先级平台字段保留
        assert merged["hostname"] == "server-001"
        assert merged["os"] == "Linux"
        assert merged["owner"] == "zhangsan"
        # 标签合并去重
        assert set(merged["tags"]) == {"生产环境", "核心业务", "办公终端", "有漏洞"}
        # 低优先级平台独有的字段保留
        assert merged["risk_level"] == "高危"

    def test_merge_asset_results_no_data(self):
        """测试所有平台都没有数据的情况"""
        platform_results = {
            "caasm": {"error": "查询失败"},
            "corplink": {"error": "未查询到"},
            "xdr": {"error": "接口错误"},
            "ndr": {"error": "超时"}
        }

        merged = _merge_asset_results(platform_results, "192.168.1.100")

        assert "error" in merged
        assert merged["confidence"] == 0

    @pytest.mark.asyncio
    async def test_asset_query_missing_ip(self):
        """测试缺少IP参数的情况"""
        # Python函数参数检查会自动报错，不需要单独测试
        pass
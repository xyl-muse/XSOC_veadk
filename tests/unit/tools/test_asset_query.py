"""资产信息查询工具单元测试"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from tools.asset_query_tool import AssetQueryTool


class TestAssetQueryTool:
    """资产信息查询工具测试类"""

    @pytest.fixture
    def tool(self):
        """创建测试用的工具实例"""
        with patch('tools.asset_query_tool.get_config') as mock_get_config:
            # 模拟配置
            mock_config = MagicMock()
            mock_config.tools = {
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
                "xdr": {
                    "enabled": True,
                    "base_url": "https://xdr.example.com",
                    "api_key": "test-xdr-key"
                },
                "ndr": {
                    "enabled": True,
                    "base_url": "https://ndr.example.com",
                    "api_key": "test-ndr-key"
                }
            }
            mock_get_config.return_value = mock_config

            tool = AssetQueryTool()
            tool.logger = MagicMock()
            return tool

    @pytest.mark.asyncio
    async def test_asset_query_initialization(self, tool):
        """测试工具初始化"""
        assert tool.name == "asset_query"
        assert tool.display_name == "资产信息查询"
        assert "查询内部资产信息" in tool.description
        assert tool.caasm_enabled is True
        assert tool.corplink_enabled is True
        assert tool.xdr_enabled is True
        assert tool.ndr_enabled is True

    @pytest.mark.asyncio
    async def test_query_caasm_success(self, tool):
        """测试CAASM平台查询成功"""
        mock_response_data = {
            "code": "Success",
            "data": {
                "hostIp": "192.168.1.100",
                "hostName": "server-001",
                "os": "Linux",
                "osVersion": "CentOS 7.9",
                "department": "技术部",
                "owner": "zhangsan",
                "email": "zhangsan@company.com",
                "riskLevel": "high",
                "riskTag": ["服务器失陷", "后门"],
                "vulnCount": 5
            }
        }

        with patch('httpx.AsyncClient.get') as mock_get:
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_response_data
            mock_get.return_value.__aenter__.return_value = mock_resp

            with patch('httpx.AsyncClient.post') as mock_post:
                mock_post_resp = AsyncMock()
                mock_post_resp.status_code = 200
                mock_post_resp.json.return_value = {"code": "Success", "data": {"item": []}}
                mock_post.return_value.__aenter__.return_value = mock_post_resp

                result = await tool._query_caasm("192.168.1.100")

                assert "error" not in result
                assert result["platform"] == "caasm"
                assert result["ip"] == "192.168.1.100"
                assert result["hostname"] == "server-001"
                assert result["os"] == "Linux"
                assert result["owner"] == "zhangsan"
                assert result["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_query_corplink_success(self, tool):
        """测试Corplink平台查询成功"""
        mock_response_data = {
            "code": 0,
            "data": {
                "items": [
                    {
                        "ip": "192.168.2.100",
                        "deviceName": "PC-001",
                        "os": "Windows 10",
                        "osVersion": "22H2",
                        "departmentName": "市场部",
                        "userName": "lisi",
                        "userEmail": "lisi@company.com",
                        "deviceType": "PC",
                        "lastOnlineTime": "2026-03-31 10:00:00"
                    }
                ]
            }
        }

        with patch('httpx.AsyncClient.get') as mock_get:
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_response_data
            mock_get.return_value.__aenter__.return_value = mock_resp

            result = await tool._query_corplink("192.168.2.100")

            assert "error" not in result
            assert result["platform"] == "corplink"
            assert result["asset_type"] == "endpoint"
            assert result["ip"] == "192.168.2.100"
            assert result["hostname"] == "PC-001"
            assert result["os"] == "Windows 10"
            assert result["owner"] == "lisi"

    @pytest.mark.asyncio
    async def test_query_xdr_success(self, tool):
        """测试XDR平台查询成功"""
        mock_response_data = {
            "code": "Success",
            "data": {
                "item": [
                    {
                        "hostIp": "192.168.1.100",
                        "hostAssetId": 12345,
                        "hostName": "server-001",
                        "severity": 3,
                        "riskTag": ["高危漏洞", "暴力破解"],
                        "totalVulNumber": 10,
                        "highlyExploitableVulNumber": 3,
                        "branchName": "北京总部",
                        "hostGroups": ["核心业务组"]
                    },
                    {
                        "hostIp": "192.168.1.101",
                        "hostName": "server-002"
                    }
                ]
            }
        }

        with patch('httpx.AsyncClient.post') as mock_post:
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_response_data
            mock_post.return_value.__aenter__.return_value = mock_resp

            result = await tool._query_xdr("192.168.1.100")

            assert "error" not in result
            assert result["platform"] == "xdr"
            assert result["ip"] == "192.168.1.100"
            assert result["risk_level"] == "高危"
            assert result["total_vulnerability_count"] == 10
            assert result["high_risk_vulnerability_count"] == 3

    def test_merge_asset_results(self, tool):
        """测试多平台结果合并逻辑"""
        platform_results = {
            "caasm": {
                "platform": "caasm",
                "ip": "192.168.1.100",
                "hostname": "server-001",
                "os": "Linux",
                "owner": "zhangsan",
                "risk_level": "high",
                "risk_tags": ["失陷"]
            },
            "xdr": {
                "platform": "xdr",
                "ip": "192.168.1.100",
                "hostname": "prod-server-001",
                "risk_level": "高危",
                "risk_tags": ["漏洞"],
                "total_vulnerability_count": 5
            },
            "ndr": {
                "error": "未查询到数据"
            }
        }

        merged = tool._merge_asset_results(platform_results, "192.168.1.100")

        assert merged["asset_ip"] == "192.168.1.100"
        assert merged["source_platforms"] == ["caasm", "xdr"]
        assert merged["confidence"] == 50
        # CAASM优先级高，hostname保留CAASM的
        assert merged["hostname"] == "server-001"
        # 列表合并去重
        assert set(merged["risk_tags"]) == {"失陷", "漏洞"}
        # XDR独有的字段保留
        assert merged["total_vulnerability_count"] == 5

    def test_merge_asset_results_no_data(self, tool):
        """测试所有平台都没有数据的情况"""
        platform_results = {
            "caasm": {"error": "查询失败"},
            "corplink": {"error": "未查询到"},
            "xdr": {"error": "接口错误"},
            "ndr": {"error": "超时"}
        }

        merged = tool._merge_asset_results(platform_results, "192.168.1.100")

        assert "error" in merged
        assert merged["confidence"] == 0

    @pytest.mark.asyncio
    async def test_run_with_specific_platform(self, tool):
        """测试指定平台查询"""
        # Mock Corplink查询
        with patch.object(tool, '_query_corplink') as mock_query:
            mock_query.return_value = {
                "platform": "corplink",
                "ip": "192.168.2.100",
                "hostname": "PC-001"
            }

            result = await tool.run({
                "asset_ip": "192.168.2.100",
                "platform": "corplink"
            })

            assert result["asset_ip"] == "192.168.2.100"
            assert result["platforms_queried"] == ["corplink"]
            assert "corplink" in result["platform_results"]
            mock_query.assert_called_once_with("192.168.2.100")

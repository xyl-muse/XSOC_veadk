"""告警及风险信息查询工具单元测试"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from tools.alert_risk_query_tool import alert_risk_query, _merge_alert_results, _parse_time_range


class TestAlertRiskQueryTool:
    """告警及风险信息查询工具测试类"""

    def test_parse_time_range(self):
        """测试时间范围解析"""
        import time
        now = int(time.time())

        # 测试小时格式
        start, end = _parse_time_range("1h")
        assert end == now
        assert start == now - 3600

        # 测试天格式
        start, end = _parse_time_range("7d")
        assert end == now
        assert start == now - 7 * 86400

        # 测试时间戳范围
        start_ts = 1710000000
        end_ts = 1710086400
        start, end = _parse_time_range(f"{start_ts}-{end_ts}")
        assert start == start_ts
        assert end == end_ts

        # 测试默认24小时
        start, end = _parse_time_range("")
        assert end == now
        assert start == now - 86400

    @pytest.mark.asyncio
    @patch('tools.alert_risk_query_tool._get_config')
    @patch('tools.alert_risk_query_tool._query_xdr_alert')
    @patch('tools.alert_risk_query_tool._query_ndr_alert')
    async def test_alert_query_multi_platform(self, mock_ndr, mock_xdr, mock_get_config):
        """测试多平台告警查询"""
        # 模拟配置
        mock_get_config.return_value = {
            "xdr": {
                "enabled": True,
                "base_url": "https://xdr.example.com",
                "api_key": "test-xdr-key"
            },
            "ndr": {
                "enabled": True,
                "base_url": "https://ndr.example.com",
                "api_key": "test-ndr-key"
            },
            "corplink": {"enabled": False, "base_url": "", "api_key": ""}
        }

        # 模拟返回结果
        mock_xdr.return_value = {
            "platform": "xdr",
            "total": 2,
            "alerts": [
                {
                    "alert_id": "alert-123",
                    "alert_name": "暴力破解攻击",
                    "severity": 3,
                    "severity_code": "high",
                    "occur_time": 1710000000,
                    "source_ip": "1.2.3.4"
                },
                {
                    "alert_id": "alert-456",
                    "alert_name": "SQL注入攻击",
                    "severity": 3,
                    "severity_code": "high",
                    "occur_time": 1710003600,
                    "source_ip": "5.6.7.8"
                }
            ]
        }
        mock_ndr.return_value = {
            "platform": "ndr",
            "total": 1,
            "alerts": [{
                "alert_id": "alert-789",
                "alert_name": "端口扫描",
                "severity": 2,
                "severity_code": "medium",
                "occur_time": 1710007200,
                "source_ip": "9.10.11.12"
            }]
        }

        result = await alert_risk_query(asset_ip="192.168.1.100", time_range="24h")

        assert result["query_params"]["asset_ip"] == "192.168.1.100"
        assert "xdr" in result["platforms_queried"]
        assert "ndr" in result["platforms_queried"]
        assert result["merged_result"]["total"] == 3
        # 按时间倒序排序
        assert result["merged_result"]["alerts"][0]["alert_id"] == "alert-789"
        assert result["merged_result"]["alerts"][1]["alert_id"] == "alert-456"
        assert result["merged_result"]["alerts"][2]["alert_id"] == "alert-123"
        # 统计信息
        assert result["merged_result"]["severity_statistics"]["high"] == 2
        assert result["merged_result"]["severity_statistics"]["medium"] == 1
        mock_xdr.assert_called_once()
        mock_ndr.assert_called_once()

    @pytest.mark.asyncio
    @patch('tools.alert_risk_query_tool._get_config')
    @patch('tools.alert_risk_query_tool._query_corplink_alert')
    async def test_alert_query_corplink(self, mock_corplink, mock_get_config):
        """测试Corplink平台终端告警查询"""
        mock_get_config.return_value = {
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "ndr": {"enabled": False, "base_url": "", "api_key": ""},
            "corplink": {
                "enabled": True,
                "base_url": "https://corplink.example.com",
                "api_key": "test-corplink-key"
            }
        }

        mock_corplink.return_value = {
            "platform": "corplink",
            "total": 1,
            "alerts": [{
                "alert_id": "event-123",
                "alert_name": "病毒检测",
                "severity": 3,
                "severity_code": "high",
                "host_ip": "192.168.1.100",
                "user_name": "zhangsan",
                "virus_name": "Trojan.Generic"
            }]
        }

        result = await alert_risk_query(asset_ip="192.168.1.100", platform="corplink")

        assert result["platforms_queried"] == ["corplink"]
        assert result["merged_result"]["total"] == 1
        assert result["merged_result"]["alerts"][0]["virus_name"] == "Trojan.Generic"
        mock_corplink.assert_called_once()

    def test_merge_alert_results_severity_stats(self):
        """测试告警级别统计"""
        platform_results = {
            "xdr": {
                "platform": "xdr",
                "alerts": [
                    {"severity_code": "high", "occur_time": 1710000000},
                    {"severity_code": "medium", "occur_time": 1710000001}
                ]
            },
            "ndr": {
                "platform": "ndr",
                "alerts": [
                    {"severity_code": "critical", "occur_time": 1710000002},
                    {"severity_code": "low", "occur_time": 1710000003},
                    {"severity_code": "info", "occur_time": 1710000004}
                ]
            }
        }

        merged = _merge_alert_results(platform_results)

        assert merged["total"] == 5
        assert merged["severity_statistics"]["critical"] == 1
        assert merged["severity_statistics"]["high"] == 1
        assert merged["severity_statistics"]["medium"] == 1
        assert merged["severity_statistics"]["low"] == 1
        assert merged["severity_statistics"]["info"] == 1

    def test_merge_alert_results_no_data(self):
        """测试所有平台都没有数据的情况"""
        platform_results = {
            "xdr": {"error": "查询失败"},
            "ndr": {"error": "接口超时"},
            "corplink": {"error": "未查询到数据"}
        }

        merged = _merge_alert_results(platform_results)

        assert "error" in merged
        assert merged["total"] == 0

    @pytest.mark.asyncio
    @patch('tools.alert_risk_query_tool._get_config')
    @patch('tools.alert_risk_query_tool._query_xdr_alert')
    async def test_alert_query_severity_filter(self, mock_xdr, mock_get_config):
        """测试告警级别筛选参数传递"""
        mock_get_config.return_value = {
            "xdr": {
                "enabled": True,
                "base_url": "https://xdr.example.com",
                "api_key": "test-xdr-key"
            },
            "ndr": {"enabled": False, "base_url": "", "api_key": ""},
            "corplink": {"enabled": False, "base_url": "", "api_key": ""}
        }

        mock_xdr.return_value = {
            "platform": "xdr",
            "total": 0,
            "alerts": []
        }

        await alert_risk_query(severity=["high", "critical"], platform="xdr")

        # 检查参数是否正确传递
        call_args = mock_xdr.call_args
        query_params = call_args[0][0]
        assert query_params["severity"] == ["high", "critical"]

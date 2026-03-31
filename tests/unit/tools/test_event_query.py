"""事件信息查询工具单元测试"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from tools.event_query_tool import event_query, _merge_event_results


class TestEventQueryTool:
    """事件信息查询工具测试类"""

    @pytest.mark.asyncio
    @patch('tools.event_query_tool._get_config')
    @patch('tools.event_query_tool._query_xdr_event')
    @patch('tools.event_query_tool._query_ndr_event')
    async def test_event_query_xdr_priority(self, mock_ndr, mock_xdr, mock_get_config):
        """测试XDR平台优先查询"""
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
            }
        }

        # 模拟返回结果
        mock_xdr.return_value = {
            "platform": "xdr",
            "total": 1,
            "page": 1,
            "page_size": 10,
            "events": [{
                "event_id": "event-123",
                "event_name": "勒索软件攻击",
                "severity": 3,
                "severity_name": "高危",
                "host_ip": "192.168.1.100",
                "source_platform": "xdr"
            }]
        }
        mock_ndr.return_value = {
            "platform": "ndr",
            "total": 1,
            "page": 1,
            "page_size": 10,
            "events": [{
                "event_id": "event-123",
                "event_name": "勒索软件攻击",
                "severity": 4,
                "severity_name": "严重",
                "source_ip": "1.2.3.4",
                "source_platform": "ndr"
            }]
        }

        result = await event_query(event_id="event-123")

        assert result["query_params"]["event_id"] == "event-123"
        assert "xdr" in result["platforms_queried"]
        assert "ndr" in result["platforms_queried"]
        assert result["merged_result"]["total"] == 1
        # XDR优先级高，字段以XDR为准
        assert result["merged_result"]["events"][0]["severity"] == 3
        assert result["merged_result"]["events"][0]["severity_name"] == "高危"
        # NDR的补充字段也会被合并
        assert result["merged_result"]["events"][0]["source_ip"] == "1.2.3.4"
        mock_xdr.assert_called_once()
        mock_ndr.assert_called_once()

    @pytest.mark.asyncio
    @patch('tools.event_query_tool._get_config')
    @patch('tools.event_query_tool._query_xdr_event')
    async def test_event_query_specific_platform(self, mock_xdr, mock_get_config):
        """测试指定平台查询"""
        mock_get_config.return_value = {
            "xdr": {
                "enabled": True,
                "base_url": "https://xdr.example.com",
                "api_key": "test-xdr-key"
            },
            "ndr": {"enabled": False, "base_url": "", "api_key": ""}
        }

        mock_xdr.return_value = {
            "platform": "xdr",
            "total": 2,
            "page": 1,
            "page_size": 10,
            "events": [
                {"event_id": "event-123", "event_name": "暴力破解攻击"},
                {"event_id": "event-456", "event_name": "SQL注入攻击"}
            ]
        }

        result = await event_query(platform="xdr", page_size=10)

        assert result["platforms_queried"] == ["xdr"]
        assert result["merged_result"]["total"] == 2
        assert len(result["merged_result"]["events"]) == 2
        mock_xdr.assert_called_once()

    def test_merge_event_results_duplicate_id(self):
        """测试重复事件ID的合并逻辑"""
        platform_results = {
            "xdr": {
                "platform": "xdr",
                "total": 1,
                "events": [{
                    "event_id": "event-123",
                    "event_name": "勒索软件攻击",
                    "severity": 3,
                    "severity_name": "高危",
                    "host_ip": "192.168.1.100"
                }]
            },
            "ndr": {
                "platform": "ndr",
                "total": 1,
                "events": [{
                    "event_id": "event-123",
                    "event_name": "勒索软件攻击",
                    "source_ip": "1.2.3.4",
                    "destination_ip": "192.168.1.100",
                    "attack_type": "ransomware"
                }]
            }
        }

        merged = _merge_event_results(platform_results)

        assert merged["total"] == 1
        assert merged["source_platforms"] == ["xdr", "ndr"]
        assert merged["confidence"] == 100  # 0.7 + 0.3 = 1.0 -> 100%
        event = merged["events"][0]
        # XDR优先级高的字段保留
        assert event["severity"] == 3
        assert event["host_ip"] == "192.168.1.100"
        # NDR的补充字段合并
        assert event["source_ip"] == "1.2.3.4"
        assert event["attack_type"] == "ransomware"

    def test_merge_event_results_no_data(self):
        """测试所有平台都没有数据的情况"""
        platform_results = {
            "xdr": {"error": "查询失败"},
            "ndr": {"error": "接口超时"}
        }

        merged = _merge_event_results(platform_results)

        assert "error" in merged
        assert merged["confidence"] == 0

    @pytest.mark.asyncio
    @patch('tools.event_query_tool._get_config')
    @patch('tools.event_query_tool._query_xdr_event')
    async def test_event_query_time_range(self, mock_xdr, mock_get_config):
        """测试时间范围参数传递"""
        mock_get_config.return_value = {
            "xdr": {
                "enabled": True,
                "base_url": "https://xdr.example.com",
                "api_key": "test-xdr-key"
            },
            "ndr": {"enabled": False, "base_url": "", "api_key": ""}
        }

        mock_xdr.return_value = {
            "platform": "xdr",
            "total": 0,
            "events": []
        }

        start_time = 1710000000
        end_time = 1710086400

        await event_query(start_time=start_time, end_time=end_time, platform="xdr")

        # 检查参数是否正确传递
        call_args = mock_xdr.call_args
        query_params = call_args[0][0]
        assert query_params["start_time"] == start_time
        assert query_params["end_time"] == end_time

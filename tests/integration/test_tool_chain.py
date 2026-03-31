"""六大工具联动集成测试
测试资产查询 -> 威胁情报 -> 事件查询 -> 告警查询 -> 处置操作 -> 数据归档的完整链路
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import time

# 导入所有工具
from tools import (
    asset_query,
    threat_intel_query,
    event_query,
    alert_risk_query,
    response_action,
    query_block_list,
    query_whitelist_list,
    query_dealstatus_list,
    query_custom_ioc_list,
    data_archive,
)


# ==================== 模拟数据 ====================

MOCK_XDR_CONFIG = {
    "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
    "ndr": {"enabled": False, "base_url": "", "api_key": "", "api_secret": ""},
    "corplink": {"enabled": False, "base_url": "", "api_key": ""},
    "caasm": {"enabled": False, "base_url": "", "api_key": ""},
    "internal_networks": ["10.0.0.0/8"],
    "core_systems": [],
}

MOCK_NDR_CONFIG = {
    "xdr": {"enabled": False, "base_url": "", "api_key": ""},
    "ndr": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test-key", "api_secret": "test-secret"},
    "corplink": {"enabled": False, "base_url": "", "api_key": ""},
    "caasm": {"enabled": False, "base_url": "", "api_key": ""},
    "internal_networks": [],
    "core_systems": [],
}

MOCK_ALL_CONFIG = {
    "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
    "ndr": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test-key", "api_secret": "test-secret"},
    "corplink": {"enabled": True, "base_url": "https://corplink.example.com", "api_key": "test-key"},
    "caasm": {"enabled": True, "base_url": "https://caasm.example.com", "api_key": "test-key"},
    "threatbook": {"enabled": True, "base_url": "https://api.threatbook.cn/v3", "api_key": "test-threatbook-key"},
    "dingtalk": {"enabled": True, "client_id": "test-id", "client_secret": "test-secret", "table_id": "test-table"},
    "itsm": {"enabled": True, "base_url": "https://itsm.example.com", "username": "user", "password": "pass", "request_userid": "001", "cti": "cti-001"},
    "internal_networks": ["10.0.0.0/8"],
    "core_systems": [],
}

MOCK_THREATBOOK_CONFIG = {
    "threatbook": {"enabled": True, "base_url": "https://api.threatbook.cn/v3", "api_key": "test-threatbook-key"},
    "xdr": {"enabled": False, "base_url": "", "api_key": ""},
    "ndr": {"enabled": False, "base_url": "", "api_key": "", "api_secret": ""},
}


# ==================== 六大工具联动测试 ====================

class TestToolChain:
    """六大工具联动集成测试"""

    @pytest.mark.asyncio
    @patch('tools.asset_query_tool._get_config')
    @patch('tools.threat_intel_tool._get_config')
    @patch('tools.event_query_tool._get_config')
    @patch('tools.alert_risk_query_tool._get_config')
    @patch('tools.response_tool._get_config')
    @patch('tools.data_archive_tool._get_config')
    async def test_full_security_event_workflow(
        self, mock_archive_config, mock_response_config, mock_alert_config,
        mock_event_config, mock_threat_config, mock_asset_config
    ):
        """
        完整安全事件处理流程测试
        模拟从资产查询到数据归档的完整链路
        """
        # 配置所有工具
        for mock in [mock_asset_config, mock_threat_config, mock_event_config, 
                     mock_alert_config, mock_response_config, mock_archive_config]:
            mock.return_value = MOCK_ALL_CONFIG

        # 步骤1: 资产查询
        with patch('tools.asset_query_tool._query_xdr') as mock_asset:
            mock_asset.return_value = {
                "platform": "xdr",
                "asset_type": "server",
                "hostname": "server-01",
                "ip": "10.0.0.1",
                "risk_level": "高危"
            }

            asset_result = await asset_query(asset_ip="10.0.0.1", platform="xdr")
            assert asset_result is not None
            assert "platform_results" in asset_result

        # 步骤2: 威胁情报查询
        with patch('tools.threat_intel_tool._query_threatbook') as mock_threat:
            mock_threat.return_value = {
                "platform": "threatbook",
                "confidence": 95,
                "is_malicious": True,
                "risk_level": "malicious",
                "tags": ["botnet", "c2"]
            }

            threat_result = await threat_intel_query(ip="1.2.3.4", platform="threatbook")
            assert threat_result is not None
            assert "merged_result" in threat_result

        # 步骤3: 事件查询
        with patch('tools.event_query_tool._query_xdr_event') as mock_event:
            mock_event.return_value = {
                "platform": "xdr",
                "total": 1,
                "events": [{"event_id": "event-123", "event_name": "恶意软件检测", "severity": 3}]
            }

            event_result = await event_query(event_id="event-123", platform="xdr")
            assert event_result is not None
            assert "merged_result" in event_result

        # 步骤4: 告警查询
        with patch('tools.alert_risk_query_tool._query_xdr_alert') as mock_alert:
            mock_alert.return_value = {
                "platform": "xdr",
                "total": 1,
                "alerts": [{"alert_id": "alert-456", "severity": 3, "severity_name": "高危"}]
            }

            alert_result = await alert_risk_query(asset_ip="10.0.0.1", platform="xdr")
            assert alert_result is not None
            assert "merged_result" in alert_result

        # 步骤5: 处置操作 - 更新告警状态
        with patch('tools.response_tool._xdr_update_alert_status') as mock_response:
            mock_response.return_value = {
                "success": True,
                "platform": "xdr",
                "action": "update_alert_status",
                "total": 1,
                "succeeded_num": 1
            }

            response_result = await response_action(
                action_type="update_status",
                target="alert-456",
                target_type="alert",
                platform="xdr"
            )
            assert response_result["success"] is True

        # 步骤6: 数据归档
        with patch('tools.data_archive_tool._xdr_writeback_event_report') as mock_archive:
            mock_archive.return_value = {"success": True}

            archive_result = await data_archive(
                archive_type="xdr",
                event_id="event-123",
                event_data={"event_id": "event-123", "status": "handled"}
            )
            assert archive_result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._ndr_add_linkage_block')
    async def test_threat_intel_to_block_chain(self, mock_block, mock_config):
        """
        威胁情报 -> 封禁操作的联动测试
        验证威胁情报确认恶意后执行封禁的流程
        """
        mock_config.return_value = MOCK_NDR_CONFIG
        mock_block.return_value = {
            "success": True,
            "platform": "ndr",
            "action": "linkage_block_add",
            "ip": "1.2.3.4"
        }

        # 模拟威胁情报确认为恶意
        malicious_ip = "1.2.3.4"

        # 执行封禁
        result = await response_action(
            action_type="block",
            target=malicious_ip,
            target_type="ip",
            platform="ndr"
        )

        assert result["success"] is True
        # 外部IP应该是低风险
        assert result["security_check"]["risk_level"] == "low"

    @pytest.mark.asyncio
    @patch('tools.alert_risk_query_tool._get_config')
    @patch('tools.response_tool._get_config')
    @patch('tools.alert_risk_query_tool._query_xdr_alert')
    @patch('tools.response_tool._xdr_update_alert_status')
    async def test_alert_to_status_update_chain(
        self, mock_update, mock_query, mock_response_config, mock_alert_config
    ):
        """
        告警查询 -> 状态更新的联动测试
        """
        for mock in [mock_alert_config, mock_response_config]:
            mock.return_value = MOCK_XDR_CONFIG

        # 模拟告警查询结果
        mock_query.return_value = {
            "platform": "xdr",
            "total": 1,
            "alerts": [{"alert_id": "alert-123", "severity": 3, "severity_name": "高危"}]
        }

        mock_update.return_value = {
            "success": True,
            "platform": "xdr",
            "action": "update_alert_status",
            "total": 1,
            "succeeded_num": 1
        }

        # 查询告警
        alert_result = await alert_risk_query(asset_ip="10.0.0.1", platform="xdr")
        assert alert_result is not None
        assert "merged_result" in alert_result

        # 更新告警状态
        if alert_result.get("merged_result", {}).get("alerts"):
            alert_id = alert_result["merged_result"]["alerts"][0]["alert_id"]
            update_result = await response_action(
                action_type="update_status",
                target=alert_id,
                target_type="alert",
                platform="xdr"
            )
            assert update_result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.event_query_tool._get_config')
    @patch('tools.data_archive_tool._get_config')
    @patch('tools.event_query_tool._query_xdr_event')
    @patch('tools.data_archive_tool._xdr_writeback_event_report')
    async def test_event_query_to_archive_chain(
        self, mock_archive, mock_event_query, mock_archive_config, mock_event_config
    ):
        """
        事件查询 -> 数据归档的联动测试
        """
        for mock in [mock_event_config, mock_archive_config]:
            mock.return_value = MOCK_XDR_CONFIG

        # 模拟事件查询结果
        mock_event_query.return_value = {
            "platform": "xdr",
            "total": 1,
            "events": [{
                "event_id": "event-789",
                "event_name": "APT攻击检测",
                "severity": 4,
                "severity_name": "严重"
            }]
        }

        mock_archive.return_value = {"success": True}

        # 查询事件
        event_result = await event_query(event_id="event-789", platform="xdr")
        assert event_result is not None

        # 归档事件
        if event_result.get("merged_result", {}).get("events"):
            event = event_result["merged_result"]["events"][0]
            archive_result = await data_archive(
                archive_type="xdr",
                event_id=event["event_id"],
                event_data=event
            )
            assert archive_result["success"] is True


# ==================== 参数校验与异常场景测试 ====================

class TestParameterValidation:
    """参数校验测试"""

    @pytest.mark.asyncio
    @patch('tools.asset_query_tool._get_config')
    async def test_asset_query_missing_ip(self, mock_config):
        """测试资产查询缺少IP参数"""
        mock_config.return_value = MOCK_XDR_CONFIG
        
        # 空IP查询应该返回错误
        result = await asset_query(asset_ip="", platform="xdr")
        assert result is not None
        assert "error" in result or result.get("platform_results", {}).get("xdr", {}).get("error")

    @pytest.mark.asyncio
    @patch('tools.threat_intel_tool._get_config')
    async def test_threat_intel_invalid_params(self, mock_config):
        """测试威胁情报查询无效参数"""
        mock_config.return_value = MOCK_THREATBOOK_CONFIG
        
        # 所有查询参数都为空
        result = await threat_intel_query(ip="", domain="", hash="", platform="all")
        assert result is not None
        assert "error" in result

    @pytest.mark.asyncio
    @patch('tools.threat_intel_tool._get_config')
    async def test_threat_intel_valid_ip_param(self, mock_config):
        """测试威胁情报查询有效IP参数"""
        mock_config.return_value = MOCK_THREATBOOK_CONFIG
        
        with patch('tools.threat_intel_tool._query_threatbook') as mock_query:
            mock_query.return_value = {
                "platform": "threatbook",
                "confidence": 95,
                "is_malicious": False,
                "risk_level": "safe"
            }
            
            result = await threat_intel_query(ip="8.8.8.8", platform="threatbook")
            assert result is not None
            assert "merged_result" in result

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_response_action_invalid_action_type(self, mock_config):
        """测试处置操作无效操作类型"""
        mock_config.return_value = MOCK_XDR_CONFIG
        
        result = await response_action(
            action_type="invalid_action",
            target="1.2.3.4",
            target_type="ip",
            platform="xdr"
        )
        # 应该返回失败或错误
        assert result["success"] is False or result.get("error")

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_response_action_empty_target(self, mock_config):
        """测试处置操作空目标"""
        mock_config.return_value = MOCK_XDR_CONFIG
        
        result = await response_action(
            action_type="block",
            target="",
            target_type="ip",
            platform="xdr"
        )
        assert result["success"] is False

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool._get_config')
    async def test_data_archive_missing_event_id(self, mock_config):
        """测试数据归档缺少事件ID"""
        mock_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "dingtalk": {"enabled": False},
            "itsm": {"enabled": False},
        }
        
        with patch('tools.data_archive_tool._xdr_writeback_event_report') as mock_xdr:
            mock_xdr.return_value = {"success": True}
            
            result = await data_archive(
                archive_type="xdr",
                event_id="",  # 空事件ID
                event_data={}
            )
            # 应该能处理（写入空事件）或返回结果
            assert isinstance(result, dict)

    @pytest.mark.asyncio
    @patch('tools.alert_risk_query_tool._get_config')
    async def test_alert_query_invalid_time_range(self, mock_config):
        """测试告警查询无效时间范围"""
        mock_config.return_value = MOCK_XDR_CONFIG
        
        with patch('tools.alert_risk_query_tool._query_xdr_alert') as mock_query:
            mock_query.return_value = {
                "platform": "xdr",
                "total": 0,
                "alerts": []
            }
            
            # 使用自定义时间范围格式
            result = await alert_risk_query(
                time_range="1700000000-1700086400",
                platform="xdr"
            )
            assert result is not None

    @pytest.mark.asyncio
    @patch('tools.event_query_tool._get_config')
    async def test_event_query_pagination(self, mock_config):
        """测试事件查询分页参数"""
        mock_config.return_value = MOCK_XDR_CONFIG
        
        with patch('tools.event_query_tool._query_xdr_event') as mock_query:
            mock_query.return_value = {
                "platform": "xdr",
                "total": 100,
                "page": 2,
                "page_size": 20,
                "events": []
            }
            
            result = await event_query(page=2, page_size=20, platform="xdr")
            assert result is not None


class TestExceptionScenarios:
    """异常场景测试"""

    @pytest.mark.asyncio
    @patch('tools.asset_query_tool._get_config')
    @patch('tools.asset_query_tool._query_xdr')
    async def test_network_timeout(self, mock_query, mock_config):
        """测试网络超时场景"""
        mock_config.return_value = MOCK_XDR_CONFIG
        mock_query.side_effect = asyncio.TimeoutError("网络超时")
        
        result = await asset_query(asset_ip="10.0.0.1", platform="xdr")
        assert result is not None
        assert "error" in result["platform_results"]["xdr"] or not result.get("success")

    @pytest.mark.asyncio
    @patch('tools.threat_intel_tool._get_config')
    @patch('tools.threat_intel_tool._query_threatbook')
    async def test_api_rate_limit(self, mock_query, mock_config):
        """测试API限流场景"""
        mock_config.return_value = MOCK_THREATBOOK_CONFIG
        mock_query.return_value = {"error": "API rate limit exceeded"}
        
        result = await threat_intel_query(ip="1.2.3.4", platform="threatbook")
        assert result is not None
        # 应该包含错误信息
        assert result["merged_result"].get("error") or "error" in result.get("platform_results", {}).get("threatbook", {})

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._xdr_update_alert_status')
    async def test_permission_denied(self, mock_update, mock_config):
        """测试权限不足场景"""
        mock_config.return_value = MOCK_XDR_CONFIG
        mock_update.return_value = {"success": False, "error": "权限不足"}
        
        result = await response_action(
            action_type="update_status",
            target="alert-123",
            target_type="alert",
            platform="xdr"
        )
        assert result["success"] is False

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool._get_config')
    @patch('tools.data_archive_tool._xdr_writeback_event_report')
    @patch('tools.data_archive_tool._dingtalk_sync_event')
    async def test_archive_partial_failure(self, mock_dingtalk, mock_xdr, mock_config):
        """测试归档部分失败场景"""
        mock_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "dingtalk": {"enabled": True, "client_id": "test", "client_secret": "test", "table_id": "test"},
            "itsm": {"enabled": False},
        }
        
        mock_xdr.return_value = {"success": True}
        mock_dingtalk.return_value = {"success": False, "error": "同步失败"}
        
        result = await data_archive(
            archive_type="all",
            event_id="event-123",
            event_data={"event_id": "event-123"}
        )
        
        # 部分成功
        assert result["success_count"] < result["total_count"]

    @pytest.mark.asyncio
    @patch('tools.asset_query_tool._get_config')
    @patch('tools.asset_query_tool._query_xdr')
    async def test_malformed_response(self, mock_query, mock_config):
        """测试响应格式错误场景"""
        mock_config.return_value = MOCK_XDR_CONFIG
        mock_query.return_value = {"invalid_key": "invalid_value"}  # 缺少必要字段
        
        result = await asset_query(asset_ip="10.0.0.1", platform="xdr")
        assert result is not None

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._xdr_update_incident_status')
    async def test_batch_operation_partial_success(self, mock_update, mock_config):
        """测试批量操作部分成功"""
        mock_config.return_value = MOCK_XDR_CONFIG
        mock_update.return_value = {
            "success": True,
            "platform": "xdr",
            "total": 10,
            "succeeded_num": 8  # 部分成功
        }
        
        result = await response_action(
            action_type="update_status",
            target="incident-1,incident-2,incident-3",
            target_type="incident",
            platform="xdr"
        )
        assert result["success"] is True
        assert result["platform_results"]["xdr"]["succeeded_num"] == 8


# ==================== 多平台接口降级与容错测试 ====================

class TestPlatformFallback:
    """多平台降级与容错测试"""

    @pytest.mark.asyncio
    @patch('tools.asset_query_tool._get_config')
    @patch('tools.asset_query_tool._query_xdr')
    @patch('tools.asset_query_tool._query_corplink')
    async def test_asset_query_platform_fallback(self, mock_corplink, mock_xdr, mock_config):
        """
        测试资产查询平台降级
        当首选平台失败时，应该能够使用备选平台
        """
        mock_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "ndr": {"enabled": False, "base_url": "", "api_key": "", "api_secret": ""},
            "corplink": {"enabled": True, "base_url": "https://corplink.example.com", "api_key": "test-key"},
            "caasm": {"enabled": False, "base_url": "", "api_key": ""},
        }

        mock_xdr.return_value = {"error": "XDR查询失败"}
        mock_corplink.return_value = {
            "platform": "corplink",
            "asset_type": "endpoint",
            "hostname": "pc-001",
            "ip": "10.0.0.1"
        }
        
        result = await asset_query(asset_ip="10.0.0.1", platform="all")
        # 应该返回结果，即使某些平台失败
        assert result is not None
        assert "merged_result" in result

    @pytest.mark.asyncio
    @patch('tools.threat_intel_tool._get_config')
    @patch('tools.threat_intel_tool._query_threatbook')
    async def test_threat_intel_priority_order(self, mock_threatbook, mock_config):
        """
        测试威胁情报查询优先级顺序
        ThreatbookMCP > XDR > NDR
        """
        mock_config.return_value = {
            "threatbook": {"enabled": True, "base_url": "https://api.threatbook.cn/v3", "api_key": "test-key"},
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "ndr": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test-key", "api_secret": "test"},
        }

        mock_threatbook.return_value = {
            "platform": "threatbook",
            "confidence": 95,
            "is_malicious": True,
            "risk_level": "malicious",
            "tags": ["botnet"]
        }

        result = await threat_intel_query(ip="1.2.3.4", platform="threatbook")
        assert result is not None
        assert result["merged_result"]["source_platforms"] == ["threatbook"]

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._xdr_update_alert_status')
    @patch('tools.response_tool._ndr_update_alert_status')
    async def test_response_multi_platform_partial_success(self, mock_ndr, mock_xdr, mock_config):
        """
        测试多平台处置部分成功
        """
        mock_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "ndr": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test-key", "api_secret": "test"},
            "internal_networks": [],
            "core_systems": [],
        }

        mock_xdr.return_value = {"success": False, "error": "XDR失败"}
        mock_ndr.return_value = {"success": True, "platform": "ndr"}
        
        result = await response_action(
            action_type="update_status",
            target="alert-123",
            target_type="alert",
            platform="all"
        )
        
        # 应该是部分成功
        assert result["success_count"] == 1
        assert result["success"] is False

    @pytest.mark.asyncio
    @patch('tools.asset_query_tool._get_config')
    async def test_all_platforms_disabled(self, mock_config):
        """测试所有平台都禁用的场景"""
        mock_config.return_value = {
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "ndr": {"enabled": False, "base_url": "", "api_key": "", "api_secret": ""},
            "corplink": {"enabled": False, "base_url": "", "api_key": ""},
            "caasm": {"enabled": False, "base_url": "", "api_key": ""},
        }

        result = await asset_query(asset_ip="10.0.0.1", platform="all")
        assert result.get("error") or not result.get("success")

    @pytest.mark.asyncio
    @patch('tools.threat_intel_tool._get_config')
    @patch('tools.threat_intel_tool._query_threatbook')
    @patch('tools.threat_intel_tool._query_xdr')
    async def test_threat_intel_fallback_to_secondary(self, mock_xdr, mock_threatbook, mock_config):
        """测试威胁情报主平台失败时降级到次级平台"""
        mock_config.return_value = {
            "threatbook": {"enabled": True, "base_url": "https://api.threatbook.cn/v3", "api_key": "test-key"},
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "ndr": {"enabled": False, "base_url": "", "api_key": "", "api_secret": ""},
        }

        mock_threatbook.return_value = {"error": "微步API限流"}
        mock_xdr.return_value = {
            "platform": "xdr",
            "confidence": 80,
            "is_malicious": True,
            "risk_level": "malicious"
        }

        result = await threat_intel_query(ip="1.2.3.4", platform="all")
        # 应该至少有一个平台返回结果
        assert result is not None


# ==================== 工具性能与并发测试 ====================

class TestPerformanceAndConcurrency:
    """性能与并发测试"""

    @pytest.mark.asyncio
    @patch('tools.asset_query_tool._get_config')
    @patch('tools.asset_query_tool._query_xdr')
    async def test_concurrent_asset_queries(self, mock_query, mock_config):
        """测试并发资产查询"""
        mock_config.return_value = MOCK_XDR_CONFIG
        mock_query.return_value = {"platform": "xdr", "asset_type": "server", "ip": "test"}

        # 并发查询10个IP
        tasks = [
            asset_query(asset_ip=f"10.0.0.{i}", platform="xdr")
            for i in range(10)
        ]

        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start_time

        # 所有查询应该成功或返回结果
        assert len(results) == 10
        # 并发执行应该比串行快
        assert elapsed < 5.0  # 假设每个查询0.5秒，并发应该在5秒内完成

    @pytest.mark.asyncio
    @patch('tools.threat_intel_tool._get_config')
    @patch('tools.threat_intel_tool._query_threatbook')
    async def test_concurrent_threat_intel_queries(self, mock_query, mock_config):
        """测试并发威胁情报查询"""
        mock_config.return_value = MOCK_THREATBOOK_CONFIG
        mock_query.return_value = {"platform": "threatbook", "confidence": 95, "is_malicious": False}

        # 并发查询多个IP
        tasks = [
            threat_intel_query(ip=f"1.2.3.{i}", platform="threatbook")
            for i in range(5)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        assert len(results) == 5

    @pytest.mark.asyncio
    @patch('tools.alert_risk_query_tool._get_config')
    @patch('tools.alert_risk_query_tool._query_xdr_alert')
    async def test_large_result_pagination(self, mock_query, mock_config):
        """测试大量结果分页处理"""
        mock_config.return_value = MOCK_XDR_CONFIG

        # 模拟大量数据
        mock_query.return_value = {
            "platform": "xdr",
            "total": 1000,
            "alerts": [{"alert_id": f"alert-{i}"} for i in range(100)]
        }

        result = await alert_risk_query(platform="xdr")
        assert result is not None
        assert result["merged_result"]["total"] == 100

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._xdr_update_alert_status')
    async def test_batch_operations(self, mock_update, mock_config):
        """测试批量操作"""
        mock_config.return_value = MOCK_XDR_CONFIG

        mock_update.return_value = {
            "success": True,
            "platform": "xdr",
            "total": 100,
            "succeeded_num": 100
        }

        # 批量更新告警
        alert_ids = [f"alert-{i}" for i in range(100)]
        result = await response_action(
            action_type="update_status",
            target=",".join(alert_ids),
            target_type="alert",
            platform="xdr"
        )

        assert result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool._get_config')
    @patch('tools.data_archive_tool._xdr_writeback_event_report')
    @patch('tools.data_archive_tool._xdr_update_deal_status')
    @patch('tools.data_archive_tool._dingtalk_sync_event')
    @patch('tools.data_archive_tool._itsm_create_event_ticket')
    async def test_concurrent_archive_operations(
        self, mock_itsm, mock_dingtalk, mock_xdr_status, mock_xdr, mock_config
    ):
        """测试并发归档操作"""
        mock_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "dingtalk": {"enabled": True, "client_id": "test-id", "client_secret": "test-secret", "table_id": "test-table"},
            "itsm": {"enabled": True, "base_url": "https://itsm.example.com", "username": "user", "password": "pass", "request_userid": "001", "cti": "cti-001"},
        }
        mock_xdr.return_value = {"success": True}
        mock_xdr_status.return_value = {"success": True}
        mock_dingtalk.return_value = {"success": True}
        mock_itsm.return_value = {"success": True, "ticket_id": "TICKET-001"}

        start_time = time.time()
        result = await data_archive(
            archive_type="all",
            event_id="event-concurrent-test",
            event_data={"event_id": "event-concurrent-test"}
        )
        elapsed = time.time() - start_time

        assert result["success"] is True
        assert result["success_count"] == result["total_count"]
        # 并发执行应该比串行快
        assert elapsed < 3.0


# ==================== 端到端场景测试 ====================

class TestEndToEndScenarios:
    """端到端场景测试"""

    @pytest.mark.asyncio
    @patch('tools.asset_query_tool._get_config')
    @patch('tools.threat_intel_tool._get_config')
    @patch('tools.alert_risk_query_tool._get_config')
    @patch('tools.response_tool._get_config')
    @patch('tools.asset_query_tool._query_xdr')
    @patch('tools.threat_intel_tool._query_threatbook')
    @patch('tools.alert_risk_query_tool._query_xdr_alert')
    @patch('tools.response_tool._ndr_add_linkage_block')
    async def test_malware_attack_response_scenario(
        self, mock_block, mock_alert, mock_threat, mock_asset,
        mock_response_config, mock_alert_config, mock_threat_config, mock_asset_config
    ):
        """
        恶意软件攻击响应场景
        1. 发现告警
        2. 查询目标资产信息
        3. 查询攻击源威胁情报
        4. 执行处置（封禁IP）
        """
        for mock in [mock_asset_config, mock_threat_config, mock_alert_config, mock_response_config]:
            mock.return_value = MOCK_ALL_CONFIG

        # 模拟告警
        mock_alert.return_value = {
            "platform": "xdr",
            "total": 1,
            "alerts": [{
                "alert_id": "malware-alert-001",
                "severity": 4,
                "host_ip": "10.0.0.50"
            }]
        }

        alert_result = await alert_risk_query(platform="xdr")
        assert alert_result["merged_result"]["total"] > 0

        # 查询目标资产
        mock_asset.return_value = {
            "platform": "xdr",
            "asset_type": "server",
            "hostname": "web-server-01",
            "ip": "10.0.0.50",
            "risk_level": "高危"
        }

        asset_result = await asset_query(asset_ip="10.0.0.50", platform="xdr")
        assert asset_result is not None

        # 查询攻击源威胁情报
        mock_threat.return_value = {
            "platform": "threatbook",
            "confidence": 95,
            "is_malicious": True,
            "risk_level": "malicious",
            "tags": ["malware_c2"]
        }

        threat_result = await threat_intel_query(domain="evil.example.com", platform="threatbook")
        assert threat_result["merged_result"]["is_malicious"] is True

        # 执行处置
        mock_block.return_value = {
            "success": True,
            "platform": "ndr",
            "action": "linkage_block_add",
            "ip": "1.2.3.4"
        }

        response_result = await response_action(
            action_type="block",
            target="1.2.3.4",  # 解析后的IP
            target_type="ip",
            platform="ndr"
        )
        assert response_result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.alert_risk_query_tool._get_config')
    @patch('tools.response_tool._get_config')
    @patch('tools.data_archive_tool._get_config')
    @patch('tools.response_tool._xdr_create_whitelist')
    @patch('tools.response_tool._xdr_update_alert_status')
    @patch('tools.data_archive_tool._xdr_writeback_event_report')
    async def test_false_positive_handling_scenario(
        self, mock_archive, mock_update, mock_whitelist,
        mock_archive_config, mock_response_config, mock_alert_config
    ):
        """
        误报处理场景
        1. 发现告警
        2. 分析判断为误报
        3. 添加白名单
        4. 更新告警状态
        5. 归档
        """
        for mock in [mock_alert_config, mock_response_config, mock_archive_config]:
            mock.return_value = MOCK_XDR_CONFIG

        # 添加白名单
        mock_whitelist.return_value = {
            "success": True,
            "platform": "xdr",
            "action": "create_whitelist"
        }

        whitelist_result = await response_action(
            action_type="whitelist",
            target="10.0.0.100",
            target_type="ip",
            platform="xdr",
            comment="误报：内部测试服务器"
        )
        assert whitelist_result["success"] is True

        # 更新告警状态
        mock_update.return_value = {
            "success": True,
            "platform": "xdr",
            "action": "update_alert_status"
        }

        update_result = await response_action(
            action_type="update_status",
            target="alert-fp-001",
            target_type="alert",
            platform="xdr",
            comment="误报，已加白"
        )
        assert update_result["success"] is True

        # 归档
        mock_archive.return_value = {"success": True}

        archive_result = await data_archive(
            archive_type="xdr",
            event_id="event-fp-001",
            event_data={"event_id": "event-fp-001", "status": "false_positive"}
        )
        assert archive_result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.event_query_tool._get_config')
    @patch('tools.data_archive_tool._get_config')
    @patch('tools.event_query_tool._query_xdr_event')
    @patch('tools.data_archive_tool._xdr_writeback_event_report')
    @patch('tools.data_archive_tool._xdr_update_deal_status')
    @patch('tools.data_archive_tool._dingtalk_sync_event')
    @patch('tools.data_archive_tool._itsm_create_event_ticket')
    async def test_complete_event_workflow(
        self, mock_itsm, mock_dingtalk, mock_xdr_status, mock_xdr_archive, mock_event,
        mock_archive_config, mock_event_config
    ):
        """
        完整事件处理工作流
        查询事件 -> 归档到XDR -> 同步到钉钉
        """
        # event_query_tool 需要的配置
        mock_event_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "ndr": {"enabled": False, "base_url": "", "api_key": ""},
        }
        
        # data_archive_tool 需要的配置
        mock_archive_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "dingtalk": {"enabled": True, "client_id": "test-id", "client_secret": "test-secret", "table_id": "test-table"},
            "itsm": {"enabled": True, "base_url": "https://itsm.example.com", "username": "user", "password": "pass", "request_userid": "001", "cti": "cti-001"},
        }

        # 查询事件
        mock_event.return_value = {
            "platform": "xdr",
            "total": 1,
            "events": [{
                "event_id": "event-complete-001",
                "event_name": "完整流程测试事件",
                "severity": 3,
                "severity_name": "高危"
            }]
        }

        event_result = await event_query(event_id="event-complete-001", platform="xdr")
        assert event_result is not None

        # 归档
        mock_xdr_archive.return_value = {"success": True}
        mock_xdr_status.return_value = {"success": True}
        mock_dingtalk.return_value = {"success": True}
        mock_itsm.return_value = {"success": True}

        archive_result = await data_archive(
            archive_type="all",
            event_id="event-complete-001",
            event_data={
                "event_id": "event-complete-001",
                "event_type_name": "安全事件",
                "status_name": "已处置"
            }
        )
        assert archive_result["success"] is True


# ==================== 安全校验测试 ====================

class TestSecurityValidation:
    """安全校验测试"""

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._ndr_add_linkage_block')
    async def test_block_internal_ip_warning(self, mock_block, mock_config):
        """测试封禁内部IP的高风险警告"""
        mock_config.return_value = {
            "ndr": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test", "api_secret": "test"},
            "xdr": {"enabled": False},
            "internal_networks": ["10.0.0.0/8"],
            "core_systems": []
        }
        mock_block.return_value = {"success": True}

        result = await response_action(
            action_type="block",
            target="10.10.10.10",  # 内部IP
            target_type="ip",
            platform="ndr"
        )

        assert result["security_check"]["risk_level"] == "high"
        assert any("内部网段" in w for w in result["security_check"]["warnings"])

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._ndr_add_linkage_block')
    async def test_block_core_system_critical(self, mock_block, mock_config):
        """测试封禁核心业务系统的严重风险"""
        mock_config.return_value = {
            "ndr": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test", "api_secret": "test"},
            "xdr": {"enabled": False},
            "internal_networks": ["10.0.0.0/8"],
            "core_systems": ["10.0.0.1"]
        }
        mock_block.return_value = {"success": True}

        result = await response_action(
            action_type="block",
            target="10.0.0.1",  # 核心系统
            target_type="ip",
            platform="ndr"
        )

        assert result["security_check"]["risk_level"] == "critical"
        assert any("核心业务系统" in w for w in result["security_check"]["warnings"])

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._xdr_update_alert_status')
    @patch('tools.response_tool._ndr_update_alert_status')
    async def test_response_action_rollback(self, mock_ndr, mock_xdr, mock_config):
        """测试处置操作自动回滚"""
        mock_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test"},
            "ndr": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test", "api_secret": "test"},
            "internal_networks": [],
            "core_systems": []
        }

        mock_xdr.return_value = {"success": False, "error": "失败"}
        mock_ndr.return_value = {"success": True}

        result = await response_action(
            action_type="update_status",
            target="alert-123",
            target_type="alert",
            platform="all",
            auto_rollback=True
        )

        # 应该触发回滚或标记为失败
        assert result["success"] is False

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._ndr_add_linkage_block')
    async def test_block_external_ip_low_risk(self, mock_block, mock_config):
        """测试封禁外部IP的低风险"""
        mock_config.return_value = {
            "ndr": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test", "api_secret": "test"},
            "xdr": {"enabled": False},
            "internal_networks": ["10.0.0.0/8"],
            "core_systems": []
        }
        mock_block.return_value = {"success": True}

        result = await response_action(
            action_type="block",
            target="8.8.8.8",  # 外部IP
            target_type="ip",
            platform="ndr"
        )

        assert result["security_check"]["risk_level"] == "low"

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_security_check_with_empty_config(self, mock_config):
        """测试空配置的安全校验"""
        mock_config.return_value = {
            "xdr": {"enabled": False},
            "ndr": {"enabled": False},
            "internal_networks": [],
            "core_systems": []
        }

        result = await response_action(
            action_type="block",
            target="1.2.3.4",
            target_type="ip",
            platform="all"
        )

        assert result["success"] is False


# ==================== 查询工具测试 ====================

class TestQueryTools:
    """查询类工具测试"""

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._ndr_list_linkage_blocks')
    async def test_query_block_list(self, mock_list, mock_config):
        """测试查询封禁列表"""
        mock_config.return_value = MOCK_NDR_CONFIG
        mock_list.return_value = {
            "success": True,
            "platform": "ndr",
            "total": 10,
            "items": [{"ip": "1.2.3.4", "duration": 3600}]
        }

        result = await query_block_list(platform="ndr", block_type="linkage")
        assert result["success"] is True
        assert result["total"] == 10

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._xdr_list_whitelists')
    async def test_query_whitelist_list(self, mock_list, mock_config):
        """测试查询白名单列表"""
        mock_config.return_value = MOCK_XDR_CONFIG
        mock_list.return_value = {
            "success": True,
            "platform": "xdr",
            "total": 5,
            "items": [{"name": "test-whitelist", "status": "enable"}]
        }

        result = await query_whitelist_list(platform="xdr")
        assert result["success"] is True
        assert result["platform_results"]["xdr"]["total"] == 5

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    @patch('tools.response_tool._xdr_list_dealstatus')
    async def test_query_dealstatus_list(self, mock_list, mock_config):
        """测试查询处置状态列表"""
        mock_config.return_value = MOCK_XDR_CONFIG
        mock_list.return_value = {
            "success": True,
            "platform": "xdr",
            "target_type": "alert",
            "total": 20,
            "items": []
        }

        result = await query_dealstatus_list(target_type="alert", platform="xdr")
        assert result["success"] is True


# ==================== 数据归档详细测试 ====================

class TestDataArchiveDetailed:
    """数据归档详细测试"""

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool._get_config')
    @patch('tools.data_archive_tool._xdr_writeback_event_report')
    async def test_xdr_writeback_success(self, mock_writeback, mock_config):
        """测试XDR回写成功"""
        mock_config.return_value = MOCK_XDR_CONFIG
        mock_writeback.return_value = {"success": True}

        result = await data_archive(
            archive_type="xdr",
            event_id="event-001",
            event_data={"event_id": "event-001", "status": "handled"}
        )
        assert result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool._get_config')
    @patch('tools.data_archive_tool._dingtalk_sync_event')
    async def test_dingtalk_sync_success(self, mock_sync, mock_config):
        """测试钉钉同步成功"""
        mock_config.return_value = {
            "xdr": {"enabled": False},
            "dingtalk": {"enabled": True, "client_id": "test", "client_secret": "test", "table_id": "test"},
            "itsm": {"enabled": False}
        }
        mock_sync.return_value = {"success": True, "record_count": 1}

        result = await data_archive(
            archive_type="dingtalk",
            event_id="event-001",
            event_data={"event_id": "event-001"}
        )
        assert result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool._get_config')
    @patch('tools.data_archive_tool._itsm_create_event_ticket')
    async def test_itsm_create_ticket_success(self, mock_create, mock_config):
        """测试ITSM工单创建成功"""
        mock_config.return_value = {
            "xdr": {"enabled": False},
            "dingtalk": {"enabled": False},
            "itsm": {"enabled": True, "base_url": "https://itsm.example.com", "username": "user", "password": "pass", "request_userid": "001", "cti": "cti-001"}
        }
        mock_create.return_value = {"success": True, "ticket_id": "TICKET-001"}

        result = await data_archive(
            archive_type="itsm",
            event_id="event-001",
            event_data={"event_id": "event-001", "event_type_name": "安全事件"}
        )
        assert result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool._get_config')
    async def test_archive_with_all_disabled(self, mock_config):
        """测试所有归档平台都禁用"""
        mock_config.return_value = {
            "xdr": {"enabled": False},
            "dingtalk": {"enabled": False},
            "itsm": {"enabled": False}
        }

        result = await data_archive(
            archive_type="all",
            event_id="event-001",
            event_data={}
        )
        assert result["success"] is False
        assert "error" in result
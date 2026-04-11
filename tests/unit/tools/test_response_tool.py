"""处置操作工具单元测试
覆盖XDR、NDR平台的所有处置操作接口，包括安全校验、操作验证、回滚逻辑
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio

from tools.response_tool import (
    response_action,
    query_block_list,
    query_whitelist_list,
    query_dealstatus_list,
    query_custom_ioc_list,
    _security_check,
    _ip_in_network,
    _generate_ndr_auth_params,
    _xdr_update_alert_status,
    _xdr_update_incident_status,
    _xdr_list_dealstatus,
    _xdr_create_whitelist,
    _xdr_delete_whitelist,
    _xdr_update_whitelist,
    _xdr_update_whitelist_status,
    _xdr_list_whitelists,
    _ndr_add_linkage_block,
    _ndr_delete_linkage_block,
    _ndr_list_linkage_blocks,
    _ndr_add_aside_block,
    _ndr_delete_aside_block,
    _ndr_list_aside_blocks,
    _ndr_add_custom_ioc,
    _ndr_delete_custom_ioc,
    _ndr_list_custom_iocs,
    _ndr_update_alert_status,
    _ndr_add_whitelist,
    _ndr_delete_whitelist,
    _ndr_list_whitelists,
    _verify_block_result,
    _verify_whitelist_result,
    _rollback_block,
    _rollback_whitelist,
)


# ==================== 安全校验测试 ====================

class TestSecurityCheck:
    """安全校验测试类"""

    def test_security_check_internal_ip(self):
        """测试内部网段IP的安全校验"""
        config = {
            "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "core_systems": []
        }

        # 内部IP应该触发高风险警告
        result = _security_check("block", "192.168.1.100", "ip", config)
        assert result["risk_level"] == "high"
        assert len(result["warnings"]) > 0
        assert "内部网段" in result["warnings"][0]

    def test_security_check_core_system(self):
        """测试核心业务系统的安全校验"""
        config = {
            "internal_networks": ["10.0.0.0/8"],
            "core_systems": ["10.0.0.1", "10.0.0.2"]
        }

        # 核心系统应该触发严重风险警告
        result = _security_check("block", "10.0.0.1", "ip", config)
        assert result["risk_level"] == "critical"
        assert "核心业务系统" in result["warnings"][0]

    def test_security_check_external_ip(self):
        """测试外部IP的安全校验"""
        config = {
            "internal_networks": ["10.0.0.0/8", "192.168.0.0/16"],
            "core_systems": []
        }

        # 外部IP应该是低风险
        result = _security_check("block", "8.8.8.8", "ip", config)
        assert result["passed"] is True
        assert result["risk_level"] == "low"

    def test_security_check_update_status(self):
        """测试状态更新操作的安全校验"""
        config = {
            "internal_networks": ["10.0.0.0/8"],
            "core_systems": []
        }

        # 状态更新应该是低风险
        result = _security_check("update_status", "alert-123", "alert", config)
        assert result["passed"] is True
        assert result["risk_level"] == "low"

    def test_security_check_linkage_block(self):
        """测试联动阻断的安全校验"""
        config = {
            "internal_networks": ["172.16.0.0/12"],
            "core_systems": []
        }

        result = _security_check("linkage_block", "172.16.5.5", "ip", config)
        assert result["risk_level"] == "high"

    def test_security_check_aside_block(self):
        """测试旁路阻断的安全校验"""
        config = {
            "internal_networks": ["10.0.0.0/8"],
            "core_systems": ["10.10.10.10"]
        }

        result = _security_check("aside_block", "10.10.10.10", "ip", config)
        assert result["risk_level"] == "critical"


class TestIpInNetwork:
    """IP网段判断测试类"""

    def test_ip_in_network(self):
        """测试IP网段判断"""
        # 在网段内
        assert _ip_in_network("192.168.1.100", "192.168.0.0/16") is True
        assert _ip_in_network("10.10.10.10", "10.0.0.0/8") is True
        assert _ip_in_network("172.16.5.5", "172.16.0.0/12") is True

        # 不在网段内
        assert _ip_in_network("8.8.8.8", "192.168.0.0/16") is False
        assert _ip_in_network("1.1.1.1", "10.0.0.0/8") is False

        # 无效IP
        assert _ip_in_network("invalid", "192.168.0.0/16") is False

    def test_ip_in_network_edge_cases(self):
        """测试IP网段边界情况"""
        # 网段边界
        assert _ip_in_network("192.168.0.1", "192.168.0.0/24") is True
        assert _ip_in_network("192.168.0.254", "192.168.0.0/24") is True
        assert _ip_in_network("192.168.1.1", "192.168.0.0/24") is False


class TestNdrAuthParams:
    """NDR认证参数生成测试"""

    def test_generate_ndr_auth_params(self):
        """测试NDR认证参数生成"""
        api_key = "test_api_key"
        api_secret = "test_secret"

        params = _generate_ndr_auth_params(api_key, api_secret)

        assert "api_key" in params
        assert "auth_timestamp" in params
        assert "sign" in params
        assert params["api_key"] == api_key
        assert params["sign"] != ""  # 签名应该不为空


# ==================== XDR平台操作测试 ====================

class TestXdrOperations:
    """XDR平台操作测试类"""

    @pytest.mark.asyncio
    async def test_xdr_update_alert_status_success(self):
        """测试XDR更新告警状态成功"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "code": "Success",
                "data": {"total": 2, "succeededNum": 2}
            }
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _xdr_update_alert_status(
                "https://xdr.example.com",
                "test-key",
                ["alert-1", "alert-2"],
                3,
                "测试处置",
                30
            )

            assert result["success"] is True
            assert result["platform"] == "xdr"
            assert result["total"] == 2

    @pytest.mark.asyncio
    async def test_xdr_update_alert_status_failure(self):
        """测试XDR更新告警状态失败"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "code": "Error",
                "message": "权限不足"
            }
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _xdr_update_alert_status(
                "https://xdr.example.com",
                "test-key",
                ["alert-1"],
                3,
                None,
                30
            )

            assert result["success"] is False
            assert "权限不足" in result["error"]

    @pytest.mark.asyncio
    async def test_xdr_update_incident_status_success(self):
        """测试XDR更新事件状态成功"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "code": "Success",
                "data": {"total": 1, "succeededNum": 1}
            }
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _xdr_update_incident_status(
                "https://xdr.example.com",
                "test-key",
                ["incident-1"],
                40,
                "已处置",
                30
            )

            assert result["success"] is True
            assert result["action"] == "update_incident_status"

    @pytest.mark.asyncio
    async def test_xdr_list_dealstatus(self):
        """测试XDR查询处置状态列表"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "code": "Success",
                "data": {
                    "total": 10,
                    "page": 1,
                    "pageSize": 20,
                    "item": [{"id": "1", "status": "done"}]
                }
            }
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _xdr_list_dealstatus(
                "https://xdr.example.com",
                "test-key",
                "alert",
                1,
                20,
                30
            )

            assert result["success"] is True
            assert result["total"] == 10

    @pytest.mark.asyncio
    async def test_xdr_create_whitelist(self):
        """测试XDR创建白名单"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"code": "Success"}
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _xdr_create_whitelist(
                "https://xdr.example.com",
                "test-key",
                "测试白名单",
                [{"type": "srcIp", "mode": "=", "view": ["1.2.3.4"], "isIgnorecase": False}],
                ["all"],
                None,
                True,
                None,
                True,
                "测试创建",
                30
            )

            assert result["success"] is True
            assert result["action"] == "create_whitelist"

    @pytest.mark.asyncio
    async def test_xdr_delete_whitelist(self):
        """测试XDR删除白名单"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"code": "Success"}
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.delete = AsyncMock(
                return_value=mock_response
            )

            result = await _xdr_delete_whitelist(
                "https://xdr.example.com",
                "test-key",
                ["whitelist-1"],
                30
            )

            assert result["success"] is True
            assert result["deleted_ids"] == ["whitelist-1"]

    @pytest.mark.asyncio
    async def test_xdr_update_whitelist_status(self):
        """测试XDR更新白名单状态"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"code": "Success"}
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.put = AsyncMock(
                return_value=mock_response
            )

            result = await _xdr_update_whitelist_status(
                "https://xdr.example.com",
                "test-key",
                "whitelist-1",
                False,
                30
            )

            assert result["success"] is True
            assert result["status"] is False

    @pytest.mark.asyncio
    async def test_xdr_list_whitelists(self):
        """测试XDR查询白名单列表"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "code": "Success",
                "data": {
                    "total": 5,
                    "page": 1,
                    "pageSize": 20,
                    "item": [{"whiteId": "1", "name": "test"}]
                }
            }
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _xdr_list_whitelists(
                "https://xdr.example.com",
                "test-key",
                1,
                20,
                "test",
                30
            )

            assert result["success"] is True
            assert result["total"] == 5


# ==================== NDR平台操作测试 ====================

class TestNdrOperations:
    """NDR平台操作测试类"""

    @pytest.mark.asyncio
    async def test_ndr_add_linkage_block(self):
        """测试NDR添加联动阻断"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"response_code": 0}
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _ndr_add_linkage_block(
                "https://ndr.example.com",
                "test-key",
                "test-secret",
                "1.2.3.4",
                3600,
                "恶意IP",
                30
            )

            assert result["success"] is True
            assert result["action"] == "linkage_block_add"

    @pytest.mark.asyncio
    async def test_ndr_delete_linkage_block(self):
        """测试NDR删除联动阻断"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"response_code": 0}
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _ndr_delete_linkage_block(
                "https://ndr.example.com",
                "test-key",
                "test-secret",
                "1.2.3.4",
                30
            )

            assert result["success"] is True
            assert result["action"] == "linkage_block_delete"

    @pytest.mark.asyncio
    async def test_ndr_list_linkage_blocks(self):
        """测试NDR查询联动阻断列表"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "response_code": 0,
                "data": {
                    "total": 3,
                    "items": [{"ip": "1.2.3.4"}]
                }
            }
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _ndr_list_linkage_blocks(
                "https://ndr.example.com",
                "test-key",
                "test-secret",
                1,
                20,
                30
            )

            assert result["success"] is True
            assert result["total"] == 3

    @pytest.mark.asyncio
    async def test_ndr_add_aside_block(self):
        """测试NDR添加旁路阻断"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"response_code": 0}
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _ndr_add_aside_block(
                "https://ndr.example.com",
                "test-key",
                "test-secret",
                "5.6.7.8",
                7200,
                "旁路阻断",
                30
            )

            assert result["success"] is True
            assert result["action"] == "aside_block_add"

    @pytest.mark.asyncio
    async def test_ndr_add_custom_ioc(self):
        """测试NDR添加自定义IOC"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"response_code": 0}
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _ndr_add_custom_ioc(
                "https://ndr.example.com",
                "test-key",
                "test-secret",
                "ip",
                "9.9.9.9",
                "malware",
                "恶意IP",
                30
            )

            assert result["success"] is True
            assert result["action"] == "custom_ioc_add"

    @pytest.mark.asyncio
    async def test_ndr_update_alert_status(self):
        """测试NDR更新告警状态"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"response_code": 0}
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _ndr_update_alert_status(
                "https://ndr.example.com",
                "test-key",
                "test-secret",
                "alert-123",
                3,
                "已处理",
                30
            )

            assert result["success"] is True
            assert result["action"] == "update_alert_status"

    @pytest.mark.asyncio
    async def test_ndr_add_whitelist(self):
        """测试NDR添加白名单"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {"response_code": 0}
            mock_response.raise_for_status = MagicMock()
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _ndr_add_whitelist(
                "https://ndr.example.com",
                "test-key",
                "test-secret",
                "ip",
                "10.0.0.1",
                "内部服务器",
                30
            )

            assert result["success"] is True
            assert result["action"] == "whitelist_add"


# ==================== 主接口测试 ====================

class TestResponseAction:
    """主接口测试类"""

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_response_action_update_alert_status(self, mock_get_config):
        """测试更新告警状态"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "ndr": {"enabled": False, "base_url": "", "api_key": "", "api_secret": ""},
            "internal_networks": ["10.0.0.0/8"],
            "core_systems": []
        }

        with patch('tools.response_tool._xdr_update_alert_status') as mock_xdr:
            mock_xdr.return_value = {
                "success": True,
                "platform": "xdr",
                "action": "update_alert_status",
                "total": 1,
                "succeeded_num": 1
            }

            result = await response_action(
                action_type="update_status",
                target="alert-123",
                target_type="alert",
                platform="xdr",
                comment="测试处置"
            )

            assert result["success"] is True
            assert result["platforms_executed"] == ["xdr"]
            assert result["success_count"] == 1

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_response_action_update_incident_status(self, mock_get_config):
        """测试更新事件状态"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "ndr": {"enabled": False, "base_url": "", "api_key": "", "api_secret": ""},
            "internal_networks": [],
            "core_systems": []
        }

        with patch('tools.response_tool._xdr_update_incident_status') as mock_xdr:
            mock_xdr.return_value = {
                "success": True,
                "platform": "xdr",
                "action": "update_incident_status"
            }

            result = await response_action(
                action_type="update_status",
                target="incident-456",
                target_type="incident",
                platform="xdr"
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_response_action_block_ip(self, mock_get_config):
        """测试封禁IP"""
        mock_get_config.return_value = {
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "ndr_instances": {
                "ndr_south": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test-key", "api_secret": "test-secret"}
            },
            "internal_networks": ["10.0.0.0/8"],
            "core_systems": []
        }

        with patch('tools.response_tool._ndr_add_linkage_block') as mock_ndr:
            mock_ndr.return_value = {
                "success": True,
                "platform": "ndr_south",
                "action": "linkage_block_add",
                "ip": "1.2.3.4"
            }

            result = await response_action(
                action_type="block",
                target="1.2.3.4",
                target_type="ip",
                duration=7200,
                platform="ndr",
                comment="恶意IP封禁"
            )

            assert result["success"] is True
            assert result["security_check"]["risk_level"] == "low"  # 外部IP

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_response_action_block_internal_ip_warning(self, mock_get_config):
        """测试封禁内部IP的高风险警告"""
        mock_get_config.return_value = {
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "ndr_instances": {
                "ndr_south": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test-key", "api_secret": "test-secret"}
            },
            "internal_networks": ["192.168.0.0/16"],
            "core_systems": []
        }

        with patch('tools.response_tool._ndr_add_linkage_block') as mock_ndr:
            mock_ndr.return_value = {
                "success": True,
                "platform": "ndr_south",
                "action": "linkage_block_add",
                "ip": "192.168.1.100"
            }

            result = await response_action(
                action_type="block",
                target="192.168.1.100",
                target_type="ip",
                platform="ndr"
            )

            # 应该有高风险警告
            assert result["security_check"]["risk_level"] == "high"
            assert "内部网段" in result["security_check"]["warnings"][0]

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_response_action_whitelist(self, mock_get_config):
        """测试添加白名单"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "ndr_instances": {
                "ndr_south": {"enabled": False, "base_url": "", "api_key": "", "api_secret": ""}
            },
            "internal_networks": [],
            "core_systems": []
        }

        with patch('tools.response_tool._xdr_create_whitelist') as mock_xdr:
            mock_xdr.return_value = {
                "success": True,
                "platform": "xdr",
                "action": "create_whitelist"
            }

            result = await response_action(
                action_type="whitelist",
                target="8.8.8.8",
                target_type="ip",
                platform="xdr",
                comment="可信DNS"
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_response_action_no_platform(self, mock_get_config):
        """测试无可用平台的情况"""
        mock_get_config.return_value = {
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "ndr": {"enabled": False, "base_url": "", "api_key": "", "api_secret": ""},
            "internal_networks": [],
            "core_systems": []
        }

        result = await response_action(
            action_type="update_status",
            target="alert-123",
            target_type="alert",
            platform="all"
        )

        assert result["success"] is False
        assert "没有可用的操作平台" in result["error"]

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_response_action_with_auto_rollback(self, mock_get_config):
        """测试自动回滚功能"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "ndr_instances": {
                "ndr_south": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test-key", "api_secret": "test-secret"}
            },
            "internal_networks": [],
            "core_systems": []
        }

        with patch('tools.response_tool._xdr_update_alert_status') as mock_xdr:
            mock_xdr.return_value = {"success": False, "error": "操作失败"}

            with patch('tools.response_tool._ndr_update_alert_status') as mock_ndr:
                mock_ndr.return_value = {"success": True, "platform": "ndr"}

                result = await response_action(
                    action_type="update_status",
                    target="alert-123",
                    target_type="alert",
                    platform="all",
                    auto_rollback=True
                )

                assert result["success"] is False
                assert result["success_count"] == 1


class TestQueryFunctions:
    """查询函数测试类"""

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_query_block_list_linkage(self, mock_get_config):
        """测试查询联动阻断列表"""
        mock_get_config.return_value = {
            "ndr": {
                "enabled": True,
                "base_url": "https://ndr.example.com",
                "api_key": "test-key",
                "api_secret": "test-secret"
            }
        }

        with patch('tools.response_tool._ndr_list_linkage_blocks') as mock_ndr:
            mock_ndr.return_value = {
                "success": True,
                "platform": "ndr",
                "total": 5,
                "items": [{"ip": "1.2.3.4"}]
            }

            result = await query_block_list(platform="ndr", block_type="linkage", page=1, page_size=20)

            assert result["success"] is True
            assert result["total"] == 5

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_query_block_list_aside(self, mock_get_config):
        """测试查询旁路阻断列表"""
        mock_get_config.return_value = {
            "ndr": {
                "enabled": True,
                "base_url": "https://ndr.example.com",
                "api_key": "test-key",
                "api_secret": "test-secret"
            }
        }

        with patch('tools.response_tool._ndr_list_aside_blocks') as mock_ndr:
            mock_ndr.return_value = {
                "success": True,
                "platform": "ndr",
                "total": 3,
                "items": [{"ip": "5.6.7.8"}]
            }

            result = await query_block_list(platform="ndr", block_type="aside", page=1, page_size=20)

            assert result["success"] is True
            assert result["total"] == 3

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_query_block_list_xdr_not_supported(self, mock_get_config):
        """测试XDR不支持封禁列表查询"""
        mock_get_config.return_value = {}

        result = await query_block_list(platform="xdr")

        assert result["success"] is False
        assert "不支持封禁列表查询" in result["error"]

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_query_whitelist_list(self, mock_get_config):
        """测试查询白名单列表"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "ndr": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test-key", "api_secret": "test-secret"}
        }

        with patch('tools.response_tool._xdr_list_whitelists') as mock_xdr:
            mock_xdr.return_value = {"success": True, "total": 2}

            with patch('tools.response_tool._ndr_list_whitelists') as mock_ndr:
                mock_ndr.return_value = {"success": True, "total": 1}

                result = await query_whitelist_list(platform="all", page=1, page_size=20)

                assert result["success"] is True
                assert "xdr" in result["platforms_queried"]
                assert "ndr" in result["platforms_queried"]

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_query_dealstatus_list(self, mock_get_config):
        """测试查询处置状态列表"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"}
        }

        with patch('tools.response_tool._xdr_list_dealstatus') as mock_xdr:
            mock_xdr.return_value = {"success": True, "total": 10}

            result = await query_dealstatus_list(platform="xdr", target_type="alert")

            assert result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_query_custom_ioc_list(self, mock_get_config):
        """测试查询自定义IOC列表"""
        mock_get_config.return_value = {
            "ndr": {
                "enabled": True,
                "base_url": "https://ndr.example.com",
                "api_key": "test-key",
                "api_secret": "test-secret"
            }
        }

        with patch('tools.response_tool._ndr_list_custom_iocs') as mock_ndr:
            mock_ndr.return_value = {"success": True, "total": 5, "items": []}

            result = await query_custom_ioc_list(page=1, page_size=20)

            assert result["success"] is True


# ==================== 验证和回滚测试 ====================

class TestVerifyAndRollback:
    """验证和回滚测试类"""

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_verify_block_result_success(self, mock_get_config):
        """测试验证封禁结果成功"""
        mock_get_config.return_value = {
            "ndr": {
                "enabled": True,
                "base_url": "https://ndr.example.com",
                "api_key": "test-key",
                "api_secret": "test-secret"
            }
        }

        with patch('tools.response_tool._ndr_list_linkage_blocks') as mock_list:
            mock_list.return_value = {
                "success": True,
                "items": [{"ip": "1.2.3.4"}]
            }

            result = await _verify_block_result("ndr", mock_get_config.return_value, "1.2.3.4", 30)

            assert result is True

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_verify_block_result_not_found(self, mock_get_config):
        """测试验证封禁结果未找到"""
        mock_get_config.return_value = {
            "ndr": {
                "enabled": True,
                "base_url": "https://ndr.example.com",
                "api_key": "test-key",
                "api_secret": "test-secret"
            }
        }

        with patch('tools.response_tool._ndr_list_linkage_blocks') as mock_list:
            mock_list.return_value = {
                "success": True,
                "items": [{"ip": "5.6.7.8"}]
            }

            result = await _verify_block_result("ndr", mock_get_config.return_value, "1.2.3.4", 30)

            assert result is False

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_rollback_block(self, mock_get_config):
        """测试回滚封禁操作"""
        mock_get_config.return_value = {
            "ndr": {
                "enabled": True,
                "base_url": "https://ndr.example.com",
                "api_key": "test-key",
                "api_secret": "test-secret"
            }
        }

        with patch('tools.response_tool._ndr_delete_linkage_block') as mock_delete:
            mock_delete.return_value = {"success": True}

            result = await _rollback_block("ndr", mock_get_config.return_value, "1.2.3.4", 30)

            assert result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_rollback_whitelist(self, mock_get_config):
        """测试回滚白名单操作"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"}
        }

        with patch('tools.response_tool._xdr_delete_whitelist') as mock_delete:
            mock_delete.return_value = {"success": True}

            result = await _rollback_whitelist("xdr", mock_get_config.return_value, "8.8.8.8", "whitelist-1", 30)

            assert result["success"] is True

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_rollback_whitelist_missing_id(self, mock_get_config):
        """测试回滚白名单缺少ID"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"}
        }

        result = await _rollback_whitelist("xdr", mock_get_config.return_value, "8.8.8.8", None, 30)

        assert result["success"] is False
        assert "缺少whitelist_id" in result["error"]


# ==================== 边界情况和异常测试 ====================

class TestEdgeCasesAndExceptions:
    """边界情况和异常测试类"""

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_response_action_xdr_block_not_supported(self, mock_get_config):
        """测试XDR不支持封禁操作"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "ndr": {"enabled": False, "base_url": "", "api_key": "", "api_secret": ""},
            "internal_networks": [],
            "core_systems": []
        }

        result = await response_action(
            action_type="block",
            target="1.2.3.4",
            target_type="ip",
            platform="xdr"
        )

        assert result["success"] is False
        assert "暂不支持IP封禁" in result["platform_results"]["xdr"]["error"]

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_ndr_missing_api_secret(self, mock_get_config):
        """测试NDR缺少api_secret"""
        mock_get_config.return_value = {
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "ndr": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test-key", "api_secret": ""},
            "internal_networks": [],
            "core_systems": []
        }

        result = await response_action(
            action_type="block",
            target="1.2.3.4",
            target_type="ip",
            platform="ndr"
        )

        assert result["success"] is False
        assert "没有启用的NDR实例" in result["error"] or "缺少api_secret" in str(result)

    @pytest.mark.asyncio
    async def test_xdr_operations_exception(self):
        """测试XDR操作异常处理"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=Exception("网络错误")
            )

            result = await _xdr_update_alert_status(
                "https://xdr.example.com",
                "test-key",
                ["alert-1"],
                3,
                None,
                30
            )

            assert result["success"] is False
            assert "异常" in result["error"]

    @pytest.mark.asyncio
    async def test_ndr_operations_exception(self):
        """测试NDR操作异常处理"""
        with patch('tools.response_tool.httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=Exception("连接超时")
            )

            result = await _ndr_add_linkage_block(
                "https://ndr.example.com",
                "test-key",
                "test-secret",
                "1.2.3.4",
                3600,
                None,
                30
            )

            assert result["success"] is False
            assert "异常" in result["error"]

    @pytest.mark.asyncio
    @patch('tools.response_tool._get_config')
    async def test_core_system_block_critical(self, mock_get_config):
        """测试封禁核心业务系统触发严重风险"""
        mock_get_config.return_value = {
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "ndr": {"enabled": True, "base_url": "https://ndr.example.com", "api_key": "test-key", "api_secret": "test-secret"},
            "internal_networks": ["10.0.0.0/8"],
            "core_systems": ["10.10.10.10"]
        }

        with patch('tools.response_tool._ndr_add_linkage_block') as mock_ndr:
            mock_ndr.return_value = {"success": True}

            result = await response_action(
                action_type="block",
                target="10.10.10.10",
                target_type="ip",
                platform="ndr"
            )

            assert result["security_check"]["risk_level"] == "critical"
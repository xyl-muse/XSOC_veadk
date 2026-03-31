"""数据归档工具单元测试
覆盖XDR回写、钉钉同步、ITSM工单创建等接口
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import json
import base64

from tools.data_archive_tool import (
    data_archive,
    xdr_writeback,
    dingtalk_sync,
    itsm_create_ticket,
    _get_config,
    XdrSignature,
    _xdr_writeback_event_report,
    _xdr_update_deal_status,
    _dingtalk_get_access_token,
    _dingtalk_insert_records,
    _dingtalk_sync_event,
    _itsm_login,
    _itsm_create_ticket,
    _itsm_create_event_ticket,
)


# ==================== 配置测试 ====================

class TestGetConfig:
    """配置获取测试"""

    @patch.dict('os.environ', {
        'XDR_ENABLED': 'true',
        'XDR_API_BASE_URL': 'https://xdr.example.com',
        'XDR_API_KEY': 'test-api-key',
        'DINGTALK_ENABLED': 'true',
        'DINGTALK_Client_ID': 'test-client-id',
        'DINGTALK_Client_Secret': 'test-client-secret',
        'DINGTALK_TABLE_ID': 'test-table-id',
        'ITSM_ENABLED': 'true',
        'ITSM_BASE_URL': 'https://itsm.example.com',
        'ITSM_USER': 'testuser',
        'ITSM_PASSWORD': 'testpass',
    })
    def test_get_config_all_set(self):
        """测试所有配置都设置"""
        config = _get_config()
        assert config["xdr"]["enabled"] is True
        assert config["xdr"]["base_url"] == "https://xdr.example.com"
        assert config["dingtalk"]["enabled"] is True
        assert config["itsm"]["enabled"] is True

    @patch.dict('os.environ', {}, clear=True)
    def test_get_config_defaults(self):
        """测试默认配置"""
        config = _get_config()
        assert config["xdr"]["enabled"] is True  # 默认启用
        assert config["xdr"]["base_url"] == ""
        assert config["dingtalk"]["enabled"] is True


# ==================== XDR签名测试 ====================

class TestXdrSignature:
    """XDR签名认证测试"""

    def test_signature_init_with_ak_sk(self):
        """测试使用ak/sk初始化"""
        sig = XdrSignature(ak="test-ak", sk="test-sk")
        assert sig._access_key == "test-ak"
        assert sig._secret_key == "test-sk"

    def test_signature_init_missing_params(self):
        """测试缺少参数"""
        with pytest.raises(ValueError):
            XdrSignature()

    def test_signature_sign_basic(self):
        """测试基本签名功能"""
        sig = XdrSignature(ak="test-ak", sk="test-sk")
        headers = sig.sign(
            method="POST",
            url="https://xdr.example.com/api/test",
            headers={"content-type": "application/json"},
            payload='{"test": "data"}'
        )
        assert "Authorization" in headers
        assert "HMAC-SHA256" in headers["Authorization"]
        assert "test-ak" in headers["Authorization"]

    def test_signature_sign_with_params(self):
        """测试带查询参数的签名"""
        sig = XdrSignature(ak="test-ak", sk="test-sk")
        headers = sig.sign(
            method="GET",
            url="https://xdr.example.com/api/test",
            headers={},
            params={"param1": "value1"},
            payload=""
        )
        assert "Authorization" in headers


# ==================== XDR回写测试 ====================

class TestXdrWriteback:
    """XDR数据回写测试"""

    @pytest.mark.asyncio
    async def test_xdr_writeback_success(self):
        """测试XDR回写成功"""
        with patch('tools.data_archive_tool.XdrSignature') as mock_sig:
            mock_sig_instance = MagicMock()
            mock_sig.return_value = mock_sig_instance
            mock_sig_instance.sign.return_value = {
                "Authorization": "algorithm=HMAC-SHA256, Access=test, SignedHeaders=x, Signature=y"
            }

            with patch('tools.data_archive_tool.httpx.AsyncClient') as mock_client:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {"code": "Success"}

                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_response
                )

                result = await _xdr_writeback_event_report(
                    "https://xdr.example.com",
                    "test-auth-code",
                    "event-123",
                    {"event_id": "event-123", "status": "handled"},
                    30
                )

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_xdr_writeback_missing_api_key(self):
        """测试缺少API Key"""
        result = await _xdr_writeback_event_report(
            "https://xdr.example.com",
            "",  # 空API Key
            "event-123",
            {"event_id": "event-123"},
            30
        )

        assert result["success"] is False
        assert "API_KEY" in result["error"]

    @pytest.mark.asyncio
    async def test_xdr_writeback_http_error(self):
        """测试HTTP错误"""
        with patch('tools.data_archive_tool.XdrSignature') as mock_sig:
            mock_sig_instance = MagicMock()
            mock_sig.return_value = mock_sig_instance
            mock_sig_instance.sign.return_value = {"Authorization": "test"}

            with patch('tools.data_archive_tool.httpx.AsyncClient') as mock_client:
                mock_response = MagicMock()
                mock_response.status_code = 500
                mock_response.text = "Internal Server Error"

                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_response
                )

                result = await _xdr_writeback_event_report(
                    "https://xdr.example.com",
                    "test-api-key",
                    "event-123",
                    {"event_id": "event-123"},
                    30
                )

                assert result["success"] is False
                assert "500" in result["error"]


class TestXdrUpdateDealStatus:
    """XDR更新处置状态测试"""

    @pytest.mark.asyncio
    async def test_update_alert_status_success(self):
        """测试更新告警状态成功"""
        with patch('tools.data_archive_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "code": "Success",
                "data": {"total": 1, "succeededNum": 1}
            }

            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _xdr_update_deal_status(
                "https://xdr.example.com",
                "test-api-key",
                ["alert-1", "alert-2"],
                "alert",
                3,
                "已处置",
                30
            )

            assert result["success"] is True
            assert result["action"] == "update_alert_status"

    @pytest.mark.asyncio
    async def test_update_incident_status_success(self):
        """测试更新事件状态成功"""
        with patch('tools.data_archive_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "code": "Success",
                "data": {"total": 1, "succeededNum": 1}
            }

            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _xdr_update_deal_status(
                "https://xdr.example.com",
                "test-api-key",
                ["incident-1"],
                "incident",
                40,
                "已归档",
                30
            )

            assert result["success"] is True
            assert result["action"] == "update_incident_status"

    @pytest.mark.asyncio
    async def test_update_status_invalid_target_type(self):
        """测试无效目标类型"""
        result = await _xdr_update_deal_status(
            "https://xdr.example.com",
            "test-api-key",
            ["target-1"],
            "invalid_type",
            3,
            None,
            30
        )

        assert result["success"] is False
        assert "不支持的目标类型" in result["error"]


# ==================== 钉钉同步测试 ====================

class TestDingtalkSync:
    """钉钉AI表格同步测试"""

    @pytest.mark.asyncio
    async def test_get_access_token_success(self):
        """测试获取access_token成功"""
        with patch('tools.data_archive_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "errcode": 0,
                "access_token": "test-access-token"
            }

            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )

            result = await _dingtalk_get_access_token(
                "test-client-id",
                "test-client-secret",
                30
            )

            assert result["success"] is True
            assert result["access_token"] == "test-access-token"

    @pytest.mark.asyncio
    async def test_get_access_token_failure(self):
        """测试获取access_token失败"""
        with patch('tools.data_archive_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "errcode": 40014,
                "errmsg": "不合法的access token"
            }

            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )

            result = await _dingtalk_get_access_token(
                "invalid-client-id",
                "invalid-client-secret",
                30
            )

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_insert_records_success(self):
        """测试插入记录成功"""
        with patch('tools.data_archive_tool._dingtalk_get_access_token') as mock_token:
            mock_token.return_value = {"success": True, "access_token": "test-token"}

            with patch('tools.data_archive_tool.httpx.AsyncClient') as mock_client:
                mock_response = MagicMock()
                mock_response.json.return_value = {"errcode": 0}

                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_response
                )

                result = await _dingtalk_insert_records(
                    "test-client-id",
                    "test-client-secret",
                    "test-table-id",
                    [{"event_id": "123"}],
                    30
                )

                assert result["success"] is True

    @pytest.mark.asyncio
    async def test_insert_records_missing_config(self):
        """测试缺少配置"""
        result = await _dingtalk_insert_records(
            "",  # 空client_id
            "test-secret",
            "test-table-id",
            [{"event_id": "123"}],
            30
        )

        assert result["success"] is False
        assert "Client_ID" in result["error"]

    @pytest.mark.asyncio
    async def test_sync_event(self):
        """测试同步事件数据"""
        with patch('tools.data_archive_tool._dingtalk_insert_records') as mock_insert:
            mock_insert.return_value = {"success": True, "record_count": 1}

            event_data = {
                "event_id": "event-123",
                "event_type_name": "恶意IP攻击",
                "status_name": "已处置",
                "priority_name": "高",
                "attack_source_ip": "1.2.3.4",
                "target_asset_ip": "10.0.0.1",
                "create_time": "2026-03-31 10:00:00",
                "process_history": [],
                "raw_data": {}
            }

            result = await _dingtalk_sync_event(
                "test-client-id",
                "test-client-secret",
                "test-table-id",
                event_data,
                30
            )

            assert result["success"] is True


# ==================== ITSM工单测试 ====================

class TestItsmOperations:
    """ITSM工单操作测试"""

    @pytest.mark.asyncio
    async def test_itsm_login_success(self):
        """测试ITSM登录成功"""
        # 模拟响应：Base64编码的JSON
        response_data = {"rows": {"token": "test-token", "key": "test-key"}}
        encoded_response = base64.b64encode(json.dumps(response_data).encode()).decode()

        with patch('tools.data_archive_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.text = encoded_response

            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _itsm_login(
                "https://itsm.example.com",
                "testuser",
                "testpass",
                30
            )

            assert result["success"] is True
            assert result["token"] == "test-token"

    @pytest.mark.asyncio
    async def test_itsm_login_failure(self):
        """测试ITSM登录失败"""
        # 模拟响应：没有token
        response_data = {"rows": {}}
        encoded_response = base64.b64encode(json.dumps(response_data).encode()).decode()

        with patch('tools.data_archive_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.text = encoded_response

            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _itsm_login(
                "https://itsm.example.com",
                "wronguser",
                "wrongpass",
                30
            )

            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_itsm_create_ticket_success(self):
        """测试创建工单成功"""
        response_data = {"success": True, "data": {"ticket_id": "TICKET-001"}}
        encoded_response = base64.b64encode(json.dumps(response_data).encode()).decode()

        with patch('tools.data_archive_tool.httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.text = encoded_response

            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )

            result = await _itsm_create_ticket(
                "https://itsm.example.com",
                "test-token",
                "测试工单标题",
                "工单内容描述",
                "user-001",
                "cti-001",
                None,
                None,
                None,
                None,
                30
            )

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_itsm_create_event_ticket(self):
        """测试为事件创建工单"""
        config = {
            "base_url": "https://itsm.example.com",
            "username": "testuser",
            "password": "testpass",
            "request_userid": "user-001",
            "cti": "cti-001"
        }

        event_data = {
            "event_id": "event-123",
            "event_type_name": "恶意攻击",
            "status_name": "已处置",
            "attack_source_ip": "1.2.3.4",
            "target_asset_ip": "10.0.0.1",
            "process_history": []
        }

        with patch('tools.data_archive_tool._itsm_login') as mock_login:
            mock_login.return_value = {"success": True, "token": "test-token"}

            with patch('tools.data_archive_tool._itsm_create_ticket') as mock_create:
                mock_create.return_value = {"success": True, "ticket_id": "TICKET-001"}

                result = await _itsm_create_event_ticket(config, event_data, 30)

                assert result["success"] is True


# ==================== 主入口函数测试 ====================

class TestDataArchive:
    """主入口函数测试"""

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool._get_config')
    async def test_data_archive_xdr(self, mock_get_config):
        """测试XDR归档"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "dingtalk": {"enabled": False, "client_id": "", "client_secret": "", "table_id": ""},
            "itsm": {"enabled": False, "base_url": "", "username": "", "password": "", "request_userid": "", "cti": ""},
        }

        with patch('tools.data_archive_tool._xdr_writeback_event_report') as mock_xdr:
            mock_xdr.return_value = {"success": True}

            result = await data_archive(
                archive_type="xdr",
                event_id="event-123",
                event_data={"event_id": "event-123"}
            )

            assert result["success"] is True
            assert "xdr" in result["archive_types_executed"]

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool._get_config')
    async def test_data_archive_all(self, mock_get_config):
        """测试全部归档"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "dingtalk": {"enabled": True, "client_id": "test-id", "client_secret": "test-secret", "table_id": "test-table"},
            "itsm": {"enabled": True, "base_url": "https://itsm.example.com", "username": "user", "password": "pass", "request_userid": "001", "cti": "cti-001"},
        }

        with patch('tools.data_archive_tool._xdr_writeback_event_report') as mock_xdr:
            mock_xdr.return_value = {"success": True}

            with patch('tools.data_archive_tool._xdr_update_deal_status') as mock_status:
                mock_status.return_value = {"success": True}

                with patch('tools.data_archive_tool._dingtalk_sync_event') as mock_dingtalk:
                    mock_dingtalk.return_value = {"success": True}

                    with patch('tools.data_archive_tool._itsm_create_event_ticket') as mock_itsm:
                        mock_itsm.return_value = {"success": True}

                        result = await data_archive(
                            archive_type="all",
                            event_id="event-123",
                            event_data={"event_id": "event-123"}
                        )

                        assert result["success"] is True
                        assert result["success_count"] == 4

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool._get_config')
    async def test_data_archive_no_platform(self, mock_get_config):
        """测试无可用平台"""
        mock_get_config.return_value = {
            "xdr": {"enabled": False, "base_url": "", "api_key": ""},
            "dingtalk": {"enabled": False, "client_id": "", "client_secret": "", "table_id": ""},
            "itsm": {"enabled": False, "base_url": "", "username": "", "password": "", "request_userid": "", "cti": ""},
        }

        result = await data_archive(
            archive_type="all",
            event_id="event-123",
            event_data={"event_id": "event-123"}
        )

        assert result["success"] is False
        assert "没有可执行的归档操作" in result["error"]

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool._get_config')
    async def test_data_archive_partial_failure(self, mock_get_config):
        """测试部分失败"""
        mock_get_config.return_value = {
            "xdr": {"enabled": True, "base_url": "https://xdr.example.com", "api_key": "test-key"},
            "dingtalk": {"enabled": True, "client_id": "test-id", "client_secret": "test-secret", "table_id": "test-table"},
            "itsm": {"enabled": False, "base_url": "", "username": "", "password": "", "request_userid": "", "cti": ""},
        }

        with patch('tools.data_archive_tool._xdr_writeback_event_report') as mock_xdr:
            mock_xdr.return_value = {"success": True}

            with patch('tools.data_archive_tool._xdr_update_deal_status') as mock_status:
                mock_status.return_value = {"success": False, "error": "更新失败"}

                with patch('tools.data_archive_tool._dingtalk_sync_event') as mock_dingtalk:
                    mock_dingtalk.return_value = {"success": True}

                    result = await data_archive(
                        archive_type="all",
                        event_id="event-123",
                        event_data={"event_id": "event-123"}
                    )

                    assert result["success"] is False
                    assert result["success_count"] == 2  # xdr_writeback + dingtalk


class TestConvenienceFunctions:
    """便捷函数测试"""

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool.data_archive')
    async def test_xdr_writeback(self, mock_archive):
        """测试xdr_writeback便捷函数"""
        mock_archive.return_value = {"success": True}

        result = await xdr_writeback(
            event_id="event-123",
            event_data={"event_id": "event-123"}
        )

        assert result["success"] is True
        mock_archive.assert_called_once()

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool.data_archive')
    async def test_dingtalk_sync(self, mock_archive):
        """测试dingtalk_sync便捷函数"""
        mock_archive.return_value = {"success": True}

        result = await dingtalk_sync(event_data={"event_id": "event-123"})

        assert result["success"] is True
        mock_archive.assert_called_once()

    @pytest.mark.asyncio
    @patch('tools.data_archive_tool.data_archive')
    async def test_itsm_create_ticket(self, mock_archive):
        """测试itsm_create_ticket便捷函数"""
        mock_archive.return_value = {"success": True}

        result = await itsm_create_ticket(event_data={"event_id": "event-123"})

        assert result["success"] is True
        mock_archive.assert_called_once()


# ==================== 异常处理测试 ====================

class TestExceptionHandling:
    """异常处理测试"""

    @pytest.mark.asyncio
    async def test_xdr_writeback_exception(self):
        """测试XDR回写异常"""
        with patch('tools.data_archive_tool.XdrSignature') as mock_sig:
            mock_sig.side_effect = Exception("签名初始化失败")

            result = await _xdr_writeback_event_report(
                "https://xdr.example.com",
                "invalid-auth-code",
                "event-123",
                {"event_id": "event-123"},
                30
            )

            assert result["success"] is False
            assert "异常" in result["error"]

    @pytest.mark.asyncio
    async def test_dingtalk_exception(self):
        """测试钉钉同步异常"""
        with patch('tools.data_archive_tool._dingtalk_get_access_token') as mock_token:
            mock_token.side_effect = Exception("网络错误")

            result = await _dingtalk_insert_records(
                "test-client-id",
                "test-client-secret",
                "test-table-id",
                [{"event_id": "123"}],
                30
            )

            assert result["success"] is False
            assert "异常" in result["error"]

    @pytest.mark.asyncio
    async def test_itsm_exception(self):
        """测试ITSM异常"""
        with patch('tools.data_archive_tool.httpx.AsyncClient') as mock_client:
            mock_client.side_effect = Exception("连接超时")

            result = await _itsm_login(
                "https://itsm.example.com",
                "testuser",
                "testpass",
                30
            )

            assert result["success"] is False
            assert "异常" in result["error"]

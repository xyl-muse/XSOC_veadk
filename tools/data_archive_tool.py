"""数据归档工具
负责安全事件数据归档，支持XDR系统回写、钉钉AI表格同步、ITSM工单创建
"""
import os
import httpx
import base64
import hashlib
import hmac
import binascii
import struct
import json
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime
from urllib.parse import urlparse
import urllib.parse

from google.adk.tools.tool_context import ToolContext


def _get_config():
    """从环境变量获取工具配置"""
    return {
        "xdr": {
            "enabled": os.getenv("XDR_ENABLED", "true").lower() == "true",
            "base_url": os.getenv("XDR_API_BASE_URL", os.getenv("XDR_BASE_URL", "")),
            "api_key": os.getenv("XDR_API_KEY", ""),  # auth_code认证码
        },
        "dingtalk": {
            "enabled": os.getenv("DINGTALK_ENABLED", "true").lower() == "true",
            "client_id": os.getenv("DINGTALK_Client_ID", os.getenv("DINGTALK_CLIENT_ID", "")),
            "client_secret": os.getenv("DINGTALK_Client_Secret", os.getenv("DINGTALK_CLIENT_SECRET", "")),
            "table_id": os.getenv("DINGTALK_TABLE_ID", ""),
        },
        "itsm": {
            "enabled": os.getenv("ITSM_ENABLED", "true").lower() == "true",
            "base_url": os.getenv("ITSM_BASE_URL", ""),
            "username": os.getenv("ITSM_USER", ""),
            "password": os.getenv("ITSM_PASSWORD", ""),
            "request_userid": os.getenv("ITSM_REQUEST_USERID", ""),
            "cti": os.getenv("ITSM_CTI", "68fca869c7814cdbbe9dff32ff0ab9ea"),  # 默认CTI
        },
    }


# ==================== XDR签名认证类 ====================

class XdrSignature:
    """XDR平台API签名认证类"""
    EXTEND_HEADER = "algorithm=HMAC-SHA256, Access=%s, SignedHeaders=%s, Signature=%s"
    TOTAL_STR = "HMAC-SHA256\n%s\n%s"
    AUTH_HEADER_KEY = "Authorization"
    SDK_HOST_KEY = "sdk-host"
    CONTENT_TYPE_KEY = "content-type"
    SDK_CONTENT_TYPE_KEY = "sdk-content-type"
    DEFAULT_CONTENT_TYPE = "application/json"
    SIGN_DATE_KEY = "sign-date"
    AUTH_CODE_PARAMS = "%s+%s+%s+%s+%s+%s+%s+%s"
    AUTH_CODE_PARAMS_NUM = 14

    def __init__(self, auth_code: str = None, ak: str = None, sk: str = None):
        if ak and sk:
            self._access_key = ak
            self._secret_key = sk
        elif auth_code:
            self._access_key, self._secret_key = self._decode_auth_code(auth_code)
        else:
            raise ValueError("signature init error: need auth_code or ak/sk")

    def sign(self, method: str, url: str, headers: Dict[str, str], 
             params: Dict[str, str] = None, payload: str = "") -> Dict[str, str]:
        """
        对请求进行签名，返回带签名的headers
        """
        if not self._access_key or not self._secret_key:
            raise ValueError("access_key and secret_key can't be blank")
        
        if not url or not method:
            raise ValueError("url and method are required")

        host = self._get_host(url)
        headers, sign_date = self._header_check(headers, host)

        header_str, sign_header_str = self._sign_header_handler(headers)

        canonical_str = self._get_canonical_str(
            method, url, params or {}, header_str, payload, sign_header_str
        )

        hashed_canonical_request = self._sha256_hex_upper(canonical_str.encode("utf-8"))

        total_str = self.TOTAL_STR % (sign_date, hashed_canonical_request)

        signature = self._hmac_sha256_hex(self._secret_key, total_str)

        headers[self.AUTH_HEADER_KEY] = self.EXTEND_HEADER % (
            self._access_key, sign_header_str, signature
        )

        return headers

    def _decode_auth_code(self, auth_code: str):
        """解码auth_code获取ak和sk"""
        try:
            from Crypto.Cipher import AES
        except ImportError:
            raise ImportError("需要安装pycryptodome库: pip install pycryptodome")

        builder_str = self._reverse_hex(auth_code)
        builders = str.split(builder_str.decode("utf-8"), "|")
        if len(builders) != self.AUTH_CODE_PARAMS_NUM:
            raise ValueError("auth code decode error: invalid format")
        
        aes_secret = self._calculate_aes_secret(builders)
        ak = self._aes_cbc_decrypt(builders[9], aes_secret)
        sk = self._aes_cbc_decrypt(builders[10], aes_secret)
        return ak, sk

    def _calculate_aes_secret(self, builders: List[str]) -> bytes:
        build_str = self.AUTH_CODE_PARAMS % (
            builders[0], builders[1], builders[2], builders[3],
            builders[4], builders[5], builders[6], builders[11],
        )
        return hashlib.sha256(build_str.encode("utf-8")).digest()

    @staticmethod
    def _get_host(uri: str) -> str:
        parsed_url = urlparse(uri)
        return parsed_url.netloc

    @staticmethod
    def _header_check(headers: Dict[str, str], host: str) -> tuple:
        if headers is None:
            headers = {}
        elif not isinstance(headers, dict):
            raise ValueError("headers format illegal")
        
        if XdrSignature.SDK_HOST_KEY not in headers:
            headers[XdrSignature.SDK_HOST_KEY] = host
        if XdrSignature.CONTENT_TYPE_KEY not in headers:
            headers[XdrSignature.SDK_CONTENT_TYPE_KEY] = XdrSignature.DEFAULT_CONTENT_TYPE
        else:
            headers[XdrSignature.SDK_CONTENT_TYPE_KEY] = headers[XdrSignature.CONTENT_TYPE_KEY]
        if XdrSignature.SIGN_DATE_KEY not in headers:
            sign_date = datetime.now().strftime('%Y%m%dT%H%M%SZ')
            headers[XdrSignature.SIGN_DATE_KEY] = sign_date
        else:
            sign_date = headers[XdrSignature.SIGN_DATE_KEY]
        return headers, sign_date

    @staticmethod
    def _sign_header_handler(headers: Dict[str, str]) -> tuple:
        header_keys = [(k, v) for k, v in headers.items()]
        header_keys.sort(key=lambda x: x[0].lower())
        header_builder = []
        sign_header_builder = []
        for key, value in header_keys:
            header_builder.append(f"{key}:{value}\n")
            sign_header_builder.append(f"{key};")
        sign_header_str = "".join(sign_header_builder)
        header_str = "".join(header_builder)
        length = len(sign_header_str)
        if length > 0:
            sign_header_str = sign_header_str[:length - 1]
        return header_str, sign_header_str

    def _get_canonical_str(self, method: str, uri: str, params: Dict[str, str],
                           headers_str: str, payload: str, sign_header_str: str) -> str:
        builder = []
        builder.append(method)
        builder.append("\n")
        builder.append(self._url_transform(uri))
        builder.append("\n")
        transform = self._query_str_transform(params)
        builder.append(transform)
        builder.append("\n")
        builder.append(headers_str)
        builder.append(sign_header_str)
        builder.append("\n")
        builder.append(self._payload_transform(payload))
        return "".join(builder)

    @staticmethod
    def _url_transform(url_str: str) -> str:
        parsed_url = urlparse(url_str)
        relative_path = parsed_url.path
        if not relative_path.endswith("/"):
            relative_path += "/"
        import urllib.parse
        return urllib.parse.quote(relative_path, encoding='utf-8')

    @staticmethod
    def _query_str_transform(params: Dict[str, str]) -> str:
        if not params:
            return ""
        params = sorted(params.items(), key=lambda x: x[0])
        return urllib.parse.urlencode(params).replace("%3D", "=")

    def _payload_transform(self, payload: str) -> str:
        payload_bytes = payload.encode("utf-8")
        byte_values = [struct.unpack('b', bytes([byte]))[0] for byte in payload_bytes]
        byte_values.sort()
        new_payload = bytearray()
        for byte_value in byte_values:
            new_payload.append(byte_value)
        new_payload = self._remove_spaces(new_payload)
        return self._sha256_hex_upper(new_payload)

    @staticmethod
    def _remove_spaces(b: bytearray) -> bytearray:
        j = 0
        for i in range(len(b)):
            if b[i] != 32:
                if i != j:
                    b[j] = b[i]
                j += 1
        return b[:j]

    @staticmethod
    def _hmac_sha256_hex(secret_key: str, data: str) -> str:
        mac = hmac.new(secret_key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256)
        digest = mac.digest()
        return binascii.hexlify(digest).decode('utf-8').upper()

    @staticmethod
    def _sha256_hex_upper(b: bytes) -> str:
        hashed_b = hashlib.sha256(b).digest()
        return binascii.hexlify(hashed_b).decode('utf-8').upper()

    @staticmethod
    def _reverse_hex(auth_code: str) -> bytes:
        return binascii.unhexlify(auth_code)

    @staticmethod
    def _aes_cbc_decrypt(cipher_text: str, key: bytes) -> str:
        try:
            from Crypto.Cipher import AES
        except ImportError:
            raise ImportError("需要安装pycryptodome库: pip install pycryptodome")
        
        cipher = AES.new(key, AES.MODE_CBC, bytearray(AES.block_size))
        return cipher.decrypt(bytes.fromhex(cipher_text)).decode("utf-8")


# ==================== XDR归档操作 ====================

async def _xdr_writeback_event_report(
    base_url: str,
    api_key: str,
    event_id: str,
    event_data: Dict[str, Any],
    timeout: int
) -> Dict[str, Any]:
    """
    XDR事件报告回写
    将事件完整报告回写到XDR系统
    """
    try:
        if not api_key:
            return {"success": False, "error": "XDR_API_KEY未配置"}

        api_path = "/api/xdr/v1/appstoreapp/longjiln-event-to-agent/callback/incident"
        url = f"{base_url}{api_path}" if base_url.startswith("http") else f"https://{base_url}{api_path}"

        request_body = {
            "uuid": event_id,
            "data": event_data
        }

        payload_str = json.dumps(request_body)

        signature = XdrSignature(auth_code=api_key)
        headers = signature.sign(
            method="POST",
            url=url,
            headers={"content-type": "application/json"},
            payload=payload_str
        )

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.post(url, content=payload_str, headers=headers)

        if response.status_code >= 400:
            return {
                "success": False,
                "error": f"请求失败，状态码: {response.status_code}",
                "response": response.text
            }

        try:
            result = response.json()
            return {"success": True, "response": result}
        except json.JSONDecodeError:
            return {"success": True, "response": response.text}

    except Exception as e:
        return {"success": False, "error": f"XDR回写异常: {str(e)}"}


async def _xdr_update_deal_status(
    base_url: str,
    api_key: str,
    target_ids: List[str],
    target_type: str,
    deal_status: int,
    comment: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """
    XDR更新处置状态
    更新告警或事件的处置状态
    """
    try:
        if target_type == "alert":
            url = f"{base_url}/api/xdr/v1/alerts/dealstatus"
        elif target_type == "incident":
            url = f"{base_url}/api/xdr/v1/incidents/dealstatus"
        else:
            return {"success": False, "error": f"不支持的目标类型: {target_type}"}

        headers = {"Authorization": f"Bearer {api_key}"}

        payload = {
            "uuIds": target_ids,
            "dealStatus": deal_status,
            "dealComment": comment or "通过XSOC智能体自动归档"
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)

        if response.status_code >= 400:
            return {"success": False, "error": f"请求失败: {response.status_code}"}

        data = response.json()
        if data.get("code") != "Success":
            return {"success": False, "error": f"操作失败: {data.get('message', '未知错误')}"}

        return {
            "success": True,
            "platform": "xdr",
            "action": f"update_{target_type}_status",
            "total": data.get("data", {}).get("total", 0),
            "succeeded_num": data.get("data", {}).get("succeededNum", 0)
        }

    except Exception as e:
        return {"success": False, "error": f"XDR更新状态异常: {str(e)}"}


# ==================== 钉钉AI表格操作 ====================

async def _dingtalk_get_access_token(
    client_id: str,
    client_secret: str,
    timeout: int
) -> Dict[str, Any]:
    """获取钉钉access_token"""
    try:
        url = "https://oapi.dingtalk.com/gettoken"
        params = {
            "appkey": client_id,
            "appsecret": client_secret
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, params=params)

        data = response.json()
        if data.get("errcode") != 0:
            return {"success": False, "error": f"获取token失败: {data.get('errmsg', '未知错误')}"}

        return {"success": True, "access_token": data.get("access_token")}

    except Exception as e:
        return {"success": False, "error": f"钉钉认证异常: {str(e)}"}


async def _dingtalk_insert_records(
    client_id: str,
    client_secret: str,
    table_id: str,
    records: List[Dict[str, Any]],
    timeout: int
) -> Dict[str, Any]:
    """
    钉钉AI表格插入记录
    通过API插入数据到钉钉AI表格
    """
    try:
        if not client_id or not client_secret:
            return {"success": False, "error": "钉钉Client_ID或Client_Secret未配置"}

        if not table_id:
            return {"success": False, "error": "钉钉TABLE_ID未配置"}

        # 获取access_token
        token_result = await _dingtalk_get_access_token(client_id, client_secret, timeout)
        if not token_result.get("success"):
            return token_result

        access_token = token_result["access_token"]

        url = "https://oapi.dingtalk.com/topapi/ai_table/v1/data/insert"
        headers = {
            "Content-Type": "application/json",
            "Charset": "UTF-8"
        }

        # 构建请求数据
        payload = {
            "access_token": access_token,
            "table_id": table_id,
            "records": records
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, headers=headers, json=payload)

        data = response.json()
        if data.get("errcode") != 0:
            return {"success": False, "error": f"插入记录失败: {data.get('errmsg', '未知错误')}"}

        return {
            "success": True,
            "platform": "dingtalk",
            "action": "insert_records",
            "record_count": len(records),
            "response": data
        }

    except Exception as e:
        return {"success": False, "error": f"钉钉插入异常: {str(e)}"}


async def _dingtalk_sync_event(
    client_id: str,
    client_secret: str,
    table_id: str,
    event_data: Dict[str, Any],
    timeout: int
) -> Dict[str, Any]:
    """
    同步事件数据到钉钉AI表格
    将事件关键信息格式化后插入
    """
    try:
        # 构建记录数据
        record = {
            "event_id": event_data.get("event_id", ""),
            "event_type": event_data.get("event_type_name", ""),
            "status": event_data.get("status_name", ""),
            "priority": event_data.get("priority_name", ""),
            "attack_source_ip": event_data.get("attack_source_ip") or "未知",
            "target_asset_ip": event_data.get("target_asset_ip") or "未知",
            "create_time": event_data.get("create_time", ""),
            "process_history": json.dumps(event_data.get("process_history", []), ensure_ascii=False),
            "raw_data": json.dumps(event_data.get("raw_data", {}), ensure_ascii=False)
        }

        return await _dingtalk_insert_records(
            client_id, client_secret, table_id, [record], timeout
        )

    except Exception as e:
        return {"success": False, "error": f"同步事件异常: {str(e)}"}


# ==================== ITSM工单操作 ====================

async def _itsm_login(
    base_url: str,
    username: str,
    password: str,
    timeout: int
) -> Dict[str, Any]:
    """ITSM平台登录认证"""
    try:
        login_url = f"{base_url}/developApi/itsmDevelopApi/user/loginCheckUser"

        params = {
            "username": username,
            "password": password
        }

        # Base64编码
        login_info = base64.b64encode(json.dumps(params).encode('utf-8')).decode('utf-8')
        login_data = {"info": login_info}

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.post(login_url, data=login_data)

        # Base64解码响应
        data_decode = base64.b64decode(response.text).decode('utf-8')
        data_dict = json.loads(data_decode)

        rows = data_dict.get('rows', {})
        token = rows.get('token')
        key = rows.get('key')

        if not token:
            return {"success": False, "error": "登录失败：未获取到token"}

        return {"success": True, "token": token, "key": key}

    except Exception as e:
        return {"success": False, "error": f"ITSM登录异常: {str(e)}"}


async def _itsm_create_ticket(
    base_url: str,
    token: str,
    title: str,
    flow_memo: str,
    request_userid: str,
    cti: str,
    expect_time: Optional[str],
    event_source: Optional[str],
    app_id: Optional[str],
    group_id: Optional[str],
    timeout: int
) -> Dict[str, Any]:
    """创建ITSM工单"""
    try:
        create_url = f"{base_url}/developApi/itsmDevelopApi/itsmapi/flow_tran_api"

        # 默认期望时间为当前时间+24小时
        if not expect_time:
            from datetime import timedelta
            expect_time = (datetime.now() + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")

        data = {
            "tran_key": "api_create_event",
            "cti": cti,
            "title": title,
            "request_userid": request_userid,
            "flow_memo": flow_memo,
            "expect_time": expect_time,
            "eventsource": event_source or "eventsource016",
            "app_id": app_id or "",
            "group_id": group_id or ""
        }

        headers = {"token": token}

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.post(create_url, headers=headers, data=data)

        # Base64解码响应
        data_decode = base64.b64decode(response.text).decode('utf-8')
        result = json.loads(data_decode)

        if result.get("success") or result.get("code") == "success":
            return {
                "success": True,
                "platform": "itsm",
                "action": "create_ticket",
                "ticket_id": result.get("data", {}).get("ticket_id"),
                "response": result
            }
        else:
            return {"success": False, "error": f"创建工单失败: {result.get('message', '未知错误')}"}

    except Exception as e:
        return {"success": False, "error": f"ITSM创建工单异常: {str(e)}"}


async def _itsm_create_event_ticket(
    config: Dict[str, Any],
    event_data: Dict[str, Any],
    timeout: int
) -> Dict[str, Any]:
    """
    为安全事件创建ITSM工单
    包含登录认证和工单创建两步
    """
    try:
        base_url = config.get("base_url", "")
        username = config.get("username", "")
        password = config.get("password", "")
        request_userid = config.get("request_userid", "")
        cti = config.get("cti", "")

        if not all([base_url, username, password, request_userid]):
            return {"success": False, "error": "ITSM配置不完整"}

        # 登录获取token
        login_result = await _itsm_login(base_url, username, password, timeout)
        if not login_result.get("success"):
            return login_result

        token = login_result["token"]

        # 构建工单内容
        event_id = event_data.get("event_id", "")
        event_type = event_data.get("event_type_name", "安全事件")
        status = event_data.get("status_name", "")
        attack_source = event_data.get("attack_source_ip") or "未知"
        target_asset = event_data.get("target_asset_ip") or "未知"

        title = f"[XSOC] {event_type} - {event_id}"
        flow_memo = f"""
事件ID: {event_id}
事件类型: {event_type}
事件状态: {status}
攻击源IP: {attack_source}
目标资产IP: {target_asset}
处理时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

详细处理过程:
{json.dumps(event_data.get('process_history', []), ensure_ascii=False, indent=2)}
"""

        # 创建工单
        return await _itsm_create_ticket(
            base_url=base_url,
            token=token,
            title=title,
            flow_memo=flow_memo,
            request_userid=request_userid,
            cti=cti,
            expect_time=None,
            event_source="XSOC智能体",
            app_id="",
            group_id="",
            timeout=timeout
        )

    except Exception as e:
        return {"success": False, "error": f"ITSM工单创建异常: {str(e)}"}


# ==================== 主入口函数 ====================

async def data_archive(
    archive_type: str,
    event_id: str,
    event_data: Dict[str, Any],
    target_type: str = "incident",
    deal_status: int = 40,
    comment: Optional[str] = None,
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    数据归档工具
    执行XDR数据回写、钉钉AI表格同步、ITSM工单创建等归档操作

    Args:
        archive_type: 归档类型
            - xdr: XDR系统数据回写（事件报告）
            - xdr_status: XDR处置状态更新
            - dingtalk: 钉钉AI表格同步
            - itsm: ITSM工单创建
            - all: 执行所有归档操作
        event_id: 事件ID
        event_data: 事件数据字典
        target_type: 目标类型（用于xdr_status）：alert/incident
        deal_status: 处置状态（用于xdr_status）：0-待处置, 10-处置中, 40-已处置, 50-已挂起
        comment: 处置备注
        tool_context: 运行时上下文

    Returns:
        包含归档结果的字典
    """
    config = _get_config()
    timeout = 30

    archive_type = archive_type.lower()

    # 确定需要执行的操作
    archive_types = []
    if archive_type == "all":
        if config["xdr"]["enabled"]:
            archive_types.extend(["xdr", "xdr_status"])
        if config["dingtalk"]["enabled"]:
            archive_types.append("dingtalk")
        if config["itsm"]["enabled"]:
            archive_types.append("itsm")
    else:
        archive_types = [archive_type]

    if not archive_types:
        return {"success": False, "error": "没有可执行的归档操作，请检查配置"}

    # 并发执行归档操作
    tasks = []
    for at in archive_types:
        if at == "xdr":
            tasks.append(_xdr_writeback_event_report(
                config["xdr"]["base_url"],
                config["xdr"]["api_key"],
                event_id,
                event_data,
                timeout
            ))
        elif at == "xdr_status":
            tasks.append(_xdr_update_deal_status(
                config["xdr"]["base_url"],
                config["xdr"]["api_key"],
                [event_id],
                target_type,
                deal_status,
                comment,
                timeout
            ))
        elif at == "dingtalk":
            tasks.append(_dingtalk_sync_event(
                config["dingtalk"]["client_id"],
                config["dingtalk"]["client_secret"],
                config["dingtalk"]["table_id"],
                event_data,
                timeout
            ))
        elif at == "itsm":
            tasks.append(_itsm_create_event_ticket(
                config["itsm"],
                event_data,
                timeout
            ))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 处理结果
    archive_results = {}
    success_count = 0
    for i, at in enumerate(archive_types):
        result = results[i]
        if isinstance(result, Exception):
            archive_results[at] = {"success": False, "error": str(result)}
        else:
            archive_results[at] = result
            if result.get("success"):
                success_count += 1

    return {
        "success": success_count == len(archive_types),
        "archive_type": archive_type,
        "archive_types_executed": archive_types,
        "archive_results": archive_results,
        "success_count": success_count,
        "total_count": len(archive_types)
    }


async def xdr_writeback(
    event_id: str,
    event_data: Dict[str, Any],
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    XDR事件报告回写（便捷接口）

    Args:
        event_id: 事件ID
        event_data: 事件数据
        tool_context: 运行时上下文

    Returns:
        回写结果
    """
    return await data_archive(
        archive_type="xdr",
        event_id=event_id,
        event_data=event_data,
        tool_context=tool_context
    )


async def dingtalk_sync(
    event_data: Dict[str, Any],
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    钉钉AI表格同步（便捷接口）

    Args:
        event_data: 事件数据
        tool_context: 运行时上下文

    Returns:
        同步结果
    """
    return await data_archive(
        archive_type="dingtalk",
        event_id=event_data.get("event_id", ""),
        event_data=event_data,
        tool_context=tool_context
    )


async def itsm_create_ticket(
    event_data: Dict[str, Any],
    tool_context: ToolContext = None,
) -> Dict[str, Any]:
    """
    ITSM工单创建（便捷接口）

    Args:
        event_data: 事件数据
        tool_context: 运行时上下文

    Returns:
        工单创建结果
    """
    return await data_archive(
        archive_type="itsm",
        event_id=event_data.get("event_id", ""),
        event_data=event_data,
        tool_context=tool_context
    )
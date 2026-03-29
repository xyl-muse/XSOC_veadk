"""数据归档工具集"""
from veadk import BaseTool
from typing import Dict, Any, Optional
import requests
import json
import binascii
import hashlib
import hmac
import struct
import urllib.parse
from datetime import datetime
from Crypto.Cipher import AES
from urllib.parse import urlparse
import os


class XdrSignature(object):
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

    def __init__(self, auth_code=None, ak=None, sk=None):
        if ak and sk:
            self.__access_key = ak
            self.__secret_key = sk
        elif auth_code:
            self.__access_key, self.__secret_key = self.__decode_auth_code(auth_code)
        else:
            raise Exception("signature init error")

    def signature(self, req):
        if not self.__access_key and self.__secret_key:
            raise Exception("ak sk can't be blank")
        if not req.url or not req.method:
            raise Exception("params illegal,params can't be nil or blank except payload or query string")
        req.json = None if req.json == {} else req.json
        payload = req.data or json.dumps(req.json) if req.data or req.json else ""

        host = self.__get_host(req.url)
        req.headers, sign_date = self.__header_check(req.headers, host)

        header_str, sign_header_str = self.__sign_header_handler(req.headers)

        canonical_str = self.__get_canonical_str(req.method, req.url, req.params, header_str, payload, sign_header_str)

        hashed_canonical_request = self.__sha256_hex_upper(canonical_str.encode("utf-8"))

        total_str = self.TOTAL_STR % (sign_date, hashed_canonical_request)

        signature = self.__hmac_sha256_hex(self.__secret_key, total_str)

        req.headers[self.AUTH_HEADER_KEY] = self.EXTEND_HEADER % (self.__access_key, sign_header_str, signature)

    def __decode_auth_code(self, auth_code):
        builder_str = self.__reverse_hex(auth_code)
        builders = str.split(builder_str.decode("utf-8"), "|")
        if len(builders) != self.AUTH_CODE_PARAMS_NUM:
            raise Exception("auth code decode error")
        aes_secret = self.__calculate_aes_secret(builders)
        ak = self.__aes_cbc_decrypt(builders[9], aes_secret)
        sk = self.__aes_cbc_decrypt(builders[10], aes_secret)
        return ak, sk

    @staticmethod
    def __calculate_aes_secret(builders):
        build_str = XdrSignature.AUTH_CODE_PARAMS % (
            builders[0], builders[1], builders[2], builders[3],
            builders[4], builders[5], builders[6], builders[11],
        )
        return hashlib.sha256(build_str.encode("utf-8")).digest()

    @staticmethod
    def __get_host(uri):
        parsed_url = urllib.parse.urlparse(uri)
        return parsed_url.netloc

    @staticmethod
    def __header_check(headers, host):
        if headers is None:
            headers = {}
        elif not isinstance(headers, dict):
            raise Exception("headers format illegal")
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
    def __sign_header_handler(headers):
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

    def __get_canonical_str(self, method, uri, params, headers_str, payload, sign_header_str):
        builder = []
        builder.append(method)
        builder.append("\n")
        builder.append(self.__url_transform(uri))
        builder.append("\n")
        transform = self.__query_str_transform(params)
        builder.append(transform)
        builder.append("\n")
        builder.append(headers_str)
        builder.append(sign_header_str)
        builder.append("\n")
        builder.append(self.__payload_transform(payload))

        return "".join(builder)

    @staticmethod
    def __url_transform(url_str):
        parsed_url = urlparse(url_str)
        relative_path = parsed_url.path
        if not relative_path.endswith("/"):
            relative_path += "/"
        return urllib.parse.quote(relative_path, encoding='utf-8')

    @staticmethod
    def __query_str_transform(params):
        params = sorted(params.items(), key=lambda x: x[0])
        return urllib.parse.urlencode(params).replace("%3D", "=")

    def __payload_transform(self, payload):
        payload = payload.encode("utf-8")

        byte_values = [struct.unpack('b', bytes([byte]))[0] for byte in payload]
        byte_values.sort()
        new_payload = bytearray()
        for byte_value in byte_values:
            new_payload.append(byte_value)
        new_payload = self.__remove_spaces(new_payload)
        return self.__sha256_hex_upper(new_payload)

    @staticmethod
    def __remove_spaces(b):
        j = 0
        for i in range(len(b)):
            if b[i] != 32:
                if i != j:
                    b[j] = b[i]
                j += 1
        return b[:j]

    @staticmethod
    def __hmac_sha256_hex(secret_key, data):
        mac = hmac.new(secret_key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256)
        sum = mac.digest()
        return binascii.hexlify(sum).decode('utf-8').upper()

    @staticmethod
    def __sha256_hex_upper(b):
        hashed_b = hashlib.sha256(b).digest()
        hex_upper = binascii.hexlify(hashed_b).decode('utf-8').upper()
        return hex_upper

    @staticmethod
    def __reverse_hex(auth_code):
        return binascii.unhexlify(auth_code)

    @staticmethod
    def __aes_cbc_decrypt(cipher_text, key):
        cipher = AES.new(key, AES.MODE_CBC, bytearray(AES.block_size))
        return cipher.decrypt(bytes.fromhex(cipher_text)).decode("utf-8")


class DataArchiveTool(BaseTool):
    """数据归档工具集"""
    name: str = "data_archive"
    display_name: str = "数据归档工具"
    description: str = "负责安全事件数据归档，支持XDR系统和钉钉AI表格"

    async def run(self, archive_type: str, event_id: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行数据归档操作"""
        if archive_type == "xdr":
            return await self._xdr_data_archive(event_id, event_data)
        elif archive_type == "dingtalk":
            return await self._sync_to_dingtalk_ai_table(event_data)
        else:
            return {"status": "failed", "error": "Unsupported archive type"}

    async def _xdr_data_archive(self, event_id: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """XDR系统数据回写"""
        try:
            auth_code = os.getenv("XDR_API_KEY")
            if not auth_code:
                return {"status": "failed", "error": "XDR_API_KEY not found in environment variables"}

            xdr_host = os.getenv("XDR_HOST")
            if not xdr_host:
                return {"status": "failed", "error": "XDR_HOST not found in environment variables"}

            api_path = "/api/xdr/v1/appstoreapp/longjiln-event-to-agent/callback/incident"
            url = f"https://{xdr_host}{api_path}"

            request_body = {
                "uuid": event_id,
                "data": event_data
            }

            signature = XdrSignature(auth_code=auth_code)

            headers = {"content-type": "application/json"}
            req = requests.Request("POST", url, headers=headers, json=request_body)

            signature.signature(req=req)

            session = requests.Session()
            session.verify = False
            response = session.send(req.prepare())

            result = response.content.decode("utf-8")

            if response.status_code >= 400:
                return {"status": "failed", "error": f"请求失败，状态码: {response.status_code}, 响应: {result}"}

            try:
                json_result = json.loads(result)
                return {"status": "success", "response": json_result}
            except json.JSONDecodeError:
                return {"status": "success", "response": result}

        except Exception as e:
            return {"status": "failed", "error": str(e)}

    async def _sync_to_dingtalk_ai_table(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """同步事件数据到钉钉AI表格"""
        try:
            api_url = "https://oapi.dingtalk.com/topapi/ai_table/v1/data/insert"

            access_token = os.getenv("DINGTALK_ACCESS_TOKEN")
            table_id = os.getenv("DINGTALK_TABLE_ID")

            if not access_token or not table_id:
                return {"status": "failed", "error": "DINGTALK_ACCESS_TOKEN or DINGTALK_TABLE_ID not found in environment variables"}

            data = {
                "event_id": event_data.get("event_id"),
                "event_type": event_data.get("event_type_name"),
                "status": event_data.get("status_name"),
                "priority": event_data.get("priority_name"),
                "attack_source_ip": event_data.get("attack_source_ip") or "未知",
                "target_asset_ip": event_data.get("target_asset_ip") or "未知",
                "create_time": event_data.get("create_time"),
                "process_history": json.dumps(event_data.get("process_history", []), ensure_ascii=False),
                "raw_data": json.dumps(event_data.get("raw_data", {}), ensure_ascii=False)
            }

            headers = {
                "Content-Type": "application/json",
                "Charset": "UTF-8"
            }

            payload = {
                "access_token": access_token,
                "table_id": table_id,
                "data": data
            }

            response = requests.post(api_url, headers=headers, json=payload)
            response.raise_for_status()

            result = response.json()

            if result.get("errcode") == 0:
                return {"status": "success", "response": result}
            else:
                return {"status": "failed", "error": result.get("errmsg", "同步失败")}

        except Exception as e:
            return {"status": "failed", "error": str(e)}

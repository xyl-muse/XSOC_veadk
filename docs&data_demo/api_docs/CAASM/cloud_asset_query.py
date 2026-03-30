"""
云盘资产信息查询工具
从环境变量加载资产数据，避免敏感信息硬编码
"""
import os
import re
import json
import ipaddress
from typing import Optional, Tuple, Dict, Any, List


def load_asset_data_from_env() -> Tuple[List[Tuple[str, str, str]], List[Tuple[str, str, str]]]:
    """
    从环境变量加载资产数据
    环境变量 CLOUD_STORAGE_DATA 应为 JSON 字符串
    :return: (attribution_db, asset_type_db) 元组列表
    """
    json_str = os.environ.get("CLOUD_STORAGE_DATA", "")
    
    if not json_str:
        raise ValueError(
            "环境变量 CLOUD_STORAGE_DATA 未配置，请设置资产数据环境变量。"
            "可从 assets_data.json 文件读取内容设置。"
        )
    
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"环境变量 CLOUD_STORAGE_DATA JSON 解析失败: {e}")
    
    # 转换为元组列表格式
    attribution_db = [
        (item["region"], item["branch"], item["cidr"])
        for item in data.get("attribution_db", [])
    ]
    asset_type_db = [
        (item.get("device_type", "服务器"), item["asset_type"], item["segment"])
        for item in data.get("asset_type_db", [])
    ]
    
    return attribution_db, asset_type_db


# 模块加载时从环境变量读取数据
_attribution_db: Optional[List[Tuple[str, str, str]]] = None
_asset_type_db: Optional[List[Tuple[str, str, str]]] = None


def _get_databases() -> Tuple[List[Tuple[str, str, str]], List[Tuple[str, str, str]]]:
    """懒加载数据库，避免模块导入时失败"""
    global _attribution_db, _asset_type_db
    if _attribution_db is None or _asset_type_db is None:
        _attribution_db, _asset_type_db = load_asset_data_from_env()
    return _attribution_db, _asset_type_db


def extract_valid_ip(input_str: str) -> Optional[str]:
    """从输入字符串提取第一个有效IPv4地址，无效返回None"""
    cleaned_input = input_str.strip()
    if not cleaned_input:
        return None
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ip_matches = re.findall(ip_pattern, cleaned_input)
    if not ip_matches:
        return None
    first_ip = ip_matches[0]
    parts = first_ip.split('.')
    if len(parts) != 4:
        return None
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return None
        except ValueError:
            return None
    return first_ip


def is_ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    """判断IP是否在指定CIDR网段内"""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        network = ipaddress.IPv4Network(cidr_str, strict=False)
        return ip in network
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False


def is_ip_in_asset_segment(ip_str: str, segment_str: str) -> bool:
    """判断IP是否在资产类型库的复杂网段内（支持范围/通配符/混合/CIDR）"""
    try:
        ip = ipaddress.IPv4Address(ip_str)
        if '(' in segment_str and ')' in segment_str:
            bracket_seg = re.search(r'\((.*?)\)', segment_str).group(1)
            if is_ip_in_asset_segment(ip_str, bracket_seg):
                return True
            cidr_seg = segment_str.split('(')[0].strip()
            return is_ip_in_cidr(ip_str, cidr_seg)
        elif '-' in segment_str:
            start_seg, end_seg = segment_str.split('-', 1)
            def wildcard_to_range(seg):
                parts = seg.strip().split('.')
                if len(parts) != 4 or parts[3] != '*':
                    return seg, seg
                return f"{parts[0]}.{parts[1]}.{parts[2]}.1", f"{parts[0]}.{parts[1]}.{parts[2]}.255"
            start_ip_str, _ = wildcard_to_range(start_seg)
            end_ip_str, _ = wildcard_to_range(end_seg)
            start_ip = ipaddress.IPv4Address(start_ip_str)
            end_ip = ipaddress.IPv4Address(end_ip_str)
            return start_ip <= ip <= end_ip
        elif '*' in segment_str:
            seg_parts = segment_str.split('.')
            ip_parts = ip_str.split('.')
            if len(seg_parts) != 4 or seg_parts[3] != '*':
                return False
            return (seg_parts[0] == ip_parts[0] and
                    seg_parts[1] == ip_parts[1] and
                    seg_parts[2] == ip_parts[2] and
                    1 <= int(ip_parts[3]) <= 255)
        else:
            return is_ip_in_cidr(ip_str, segment_str)
    except (ipaddress.AddressValueError, IndexError, ValueError):
        return False


def query_attribution(ip_str: str) -> Tuple[str, str]:
    """查询归属库，返回(大区, 分公司)，未匹配返回([无], [无])"""
    attribution_db, _ = _get_databases()
    for region, branch, cidr in attribution_db:
        if is_ip_in_cidr(ip_str, cidr):
            return region, branch
    return "[无]", "[无]"


def query_asset_type(ip_str: str, dev_source_name: str) -> Tuple[str, str]:
    """
    查询资产类型（模糊匹配EDR，新增工控终端类型）
    :param ip_str: 有效IPv4地址
    :param dev_source_name: 告警来源设备名称
    :return: (device_type, asset_type) 元组
    """
    # 模糊匹配（包含EDR即判定），不区分前后字符
    if "EDR" in dev_source_name.strip():
        return "终端", "工控终端"
    # 执行资产类型库查询逻辑
    _, asset_type_db = _get_databases()
    for device_type, asset_type, segment in asset_type_db:
        if is_ip_in_asset_segment(ip_str, segment):
            return device_type, asset_type
    # 兜底返回办公PC
    return "终端", "办公终端"


def generate_result_json(ip_str: str, device_type: str, asset_type: str) -> str:
    """生成符合格式要求的JSON结果字符串"""
    region, branch = query_attribution(ip_str)
    
    json_str = (
        "{\n"
        "  \"受损资产ip\": \"" + ip_str + "\",\n"
        "  \"资产数据来源\": \"统计云盘\",\n"
        "  \"受损资产归属大区\": \"" + region + "\",\n"
        "  \"受损资产归属分公司\": \"" + branch + "\",\n"
        "  \"受损资产设备类型\": \"" + device_type + "\",\n"
        "  \"受损资产类型\": \"" + asset_type + "\"\n"
        "}"
    )
    return json_str


def userFunction(input_data: Dict[str, Any]) -> Dict[str, str]:
    """
    核心入口函数
    :param input_data: 输入字典，格式 {"hostIp": "用户查询字符串", "devSourceName": "告警来源设备名称"}
    :return: 输出字典，格式 {"result": "查询结果"}
             结果为JSON字符串或"未查询到该资产"
    """
    # 提取输入参数，增加devSourceName（默认空字符串，容错处理）
    query_str = input_data.get("hostIp", "").strip()
    dev_source_name = input_data.get("devSourceName", "").strip()
    
    # 提取有效IP
    valid_ip = extract_valid_ip(query_str)
    if valid_ip is None:
        return {"result": "未查询到该资产"}
    
    # 先模糊匹配告警来源，再获取设备类型和资产类型
    device_type, asset_type = query_asset_type(valid_ip, dev_source_name)
    
    # 生成结果并返回
    return {"result": generate_result_json(valid_ip, device_type, asset_type)}


# 提供便捷函数用于外部调用
def reload_asset_data() -> None:
    """重新加载资产数据（用于热更新场景）"""
    global _attribution_db, _asset_type_db
    _attribution_db = None
    _asset_type_db = None
    _get_databases()


if __name__ == "__main__":
    # 测试用例
    import sys
    try:
        test_input = {"hostIp": "10.0.0.1", "devSourceName": "test"}
        result = userFunction(test_input)
        print(f"测试结果: {result}")
    except ValueError as e:
        print(f"错误: {e}")
        print("请设置环境变量 CLOUD_STORAGE_DATA")
        sys.exit(1)

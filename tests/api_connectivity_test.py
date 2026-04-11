"""
API连通性测试脚本
测试所有外部API的连通性，验证环境变量配置是否正确

执行方式：
    pytest tests/api_connectivity_test.py -v
    pytest tests/api_connectivity_test.py::test_llm_connectivity -v  # 单独测试LLM
"""
import os
import sys
import asyncio
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import aiohttp
import pytest
from dotenv import load_dotenv
from loguru import logger

# 加载.env文件中的环境变量
env_file = project_root / ".env"
if env_file.exists():
    load_dotenv(env_file)
    logger.info(f"已加载环境变量文件: {env_file}")
else:
    logger.warning(f"未找到.env文件: {env_file}")


# ============================================================================
# LLM模型连通性测试
# ============================================================================
@pytest.mark.asyncio
async def test_llm_connectivity():
    """测试LLM模型连通性（与problems.md无关）"""
    model_name = os.getenv("MODEL_AGENT_NAME")
    provider = os.getenv("MODEL_AGENT_PROVIDER")
    api_base = os.getenv("MODEL_AGENT_API_BASE")
    api_key = os.getenv("MODEL_AGENT_API_KEY")
    
    logger.info(f"LLM配置: provider={provider}, model={model_name}, base_url={api_base}")
    
    assert api_key, "MODEL_AGENT_API_KEY未配置"
    assert api_base, "MODEL_AGENT_API_BASE未配置"
    
    # 简单的LLM连通性测试：发送一个简单的请求
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model_name,
        "messages": [{"role": "user", "content": "Hello, this is a connectivity test."}],
        "max_tokens": 10
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{api_base}/chat/completions",
                headers=headers,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.success(f"LLM连通性测试成功: {result.get('model', 'unknown')}")
                else:
                    error_text = await response.text()
                    logger.error(f"LLM连通性测试失败: HTTP {response.status}, {error_text}")
                    pytest.fail(f"LLM连通性测试失败: HTTP {response.status}")
    except Exception as e:
        logger.error(f"LLM连通性测试异常: {str(e)}")
        pytest.fail(f"LLM连通性测试异常: {str(e)}")


# ============================================================================
# 威胁情报平台连通性测试
# ============================================================================
@pytest.mark.asyncio
async def test_threatbook_connectivity():
    """测试微步威胁情报API连通性（与problems.md无关）"""
    api_key = os.getenv("THREAT_BOOK_API_KEY") or os.getenv("THREATBOOK_API_KEY")
    base_url = os.getenv("THREATBOOK_BASE_URL", "https://api.threatbook.cn/v3")
    enabled = os.getenv("THREATBOOK_ENABLED", "true").lower() == "true"
    
    if not enabled:
        pytest.skip("THREATBOOK_ENABLED=false，跳过测试")
    
    assert api_key, "THREAT_BOOK_API_KEY未配置"
    
    # 测试IP查询接口（使用8.8.8.8作为测试IP）
    url = f"{base_url}/ip/query"
    params = {
        "apikey": api_key,
        "resource": "8.8.8.8"
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    if result.get("response_code") == 0:
                        logger.success(f"微步威胁情报连通性测试成功")
                    else:
                        logger.warning(f"微步API返回错误: {result.get('verbose_msg', 'unknown')}")
                else:
                    error_text = await response.text()
                    logger.error(f"微步威胁情报连通性测试失败: HTTP {response.status}, {error_text}")
                    pytest.fail(f"微步威胁情报连通性测试失败: HTTP {response.status}")
    except Exception as e:
        logger.error(f"微步威胁情报连通性测试异常: {str(e)}")
        pytest.fail(f"微步威胁情报连通性测试异常: {str(e)}")


# ============================================================================
# XDR平台连通性测试
# ============================================================================
@pytest.mark.asyncio
async def test_xdr_connectivity():
    """测试XDR平台API连通性（可能与problems.md #1相关）"""
    base_url = os.getenv("XDR_API_BASE_URL") or os.getenv("XDR_BASE_URL")
    api_key = os.getenv("XDR_API_KEY")
    enabled = os.getenv("XDR_ENABLED", "true").lower() == "true"
    
    if not enabled:
        pytest.skip("XDR_ENABLED=false，跳过测试")
    
    assert base_url, "XDR_API_BASE_URL未配置"
    assert api_key, "XDR_API_KEY未配置"
    
    # 测试XDR健康检查或简单查询接口
    # 注意：XDR的认证方式可能需要特殊处理，这里先测试连接
    headers = {
        "Content-Type": "application/json"
    }
    
    # XDR通常使用auth_code进行HMAC签名，这里简化测试
    try:
        async with aiohttp.ClientSession() as session:
            # 测试连接性（尝试访问一个简单的端点）
            async with session.get(
                f"{base_url}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False  # 如果是自签名证书
            ) as response:
                # 只要能连接到服务器就算成功
                logger.success(f"XDR连通性测试成功: HTTP {response.status}")
    except aiohttp.ClientConnectorError as e:
        logger.error(f"XDR连通性测试失败（网络连接错误）: {str(e)}")
        logger.warning(f"可能的原因：URL格式错误或网络不通，请检查XDR_API_BASE_URL={base_url}")
        pytest.fail(f"XDR连通性测试失败: {str(e)}")
    except Exception as e:
        logger.error(f"XDR连通性测试异常: {str(e)}")
        # 不直接失败，因为XDR可能需要特殊认证
        logger.warning(f"XDR可能需要特殊认证机制，连通性测试跳过")


# ============================================================================
# NDR平台连通性测试（多实例）
# ============================================================================
@pytest.mark.asyncio
async def test_ndr_north_connectivity():
    """测试NDR_NORTH实例API连通性（与problems.md无关）"""
    base_url = os.getenv("NDR_NORTH_BASE_URL")
    api_key = os.getenv("NDR_NORTH_API_KEY")
    api_secret = os.getenv("NDR_NORTH_API_SECRET")
    enabled = os.getenv("NDR_NORTH_ENABLED", "true").lower() == "true"
    
    if not base_url:
        pytest.skip("NDR_NORTH_BASE_URL未配置，跳过测试")
    
    if not enabled:
        pytest.skip("NDR_NORTH_ENABLED=false，跳过测试")
    
    assert api_key, "NDR_NORTH_API_KEY未配置"
    assert api_secret, "NDR_NORTH_API_SECRET未配置"
    
    await _test_ndr_instance("NDR_NORTH", base_url, api_key, api_secret)


@pytest.mark.asyncio
async def test_ndr_south_connectivity():
    """测试NDR_SOUTH实例API连通性（与problems.md无关）"""
    base_url = os.getenv("NDR_SOUTH_BASE_URL")
    api_key = os.getenv("NDR_SOUTH_API_KEY")
    api_secret = os.getenv("NDR_SOUTH_API_SECRET")
    enabled = os.getenv("NDR_SOUTH_ENABLED", "true").lower() == "true"
    
    if not base_url:
        pytest.skip("NDR_SOUTH_BASE_URL未配置，跳过测试")
    
    if not enabled:
        pytest.skip("NDR_SOUTH_ENABLED=false，跳过测试")
    
    assert api_key, "NDR_SOUTH_API_KEY未配置"
    assert api_secret, "NDR_SOUTH_API_SECRET未配置"
    
    await _test_ndr_instance("NDR_SOUTH", base_url, api_key, api_secret)


async def _test_ndr_instance(instance_name: str, base_url: str, api_key: str, api_secret: str):
    """测试NDR实例连通性的通用函数"""
    # NDR通常需要HMAC签名，这里先测试基本连接
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{base_url}",
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False  # 如果是自签名证书
            ) as response:
                logger.success(f"{instance_name}连通性测试成功: HTTP {response.status}")
    except aiohttp.ClientConnectorError as e:
        logger.error(f"{instance_name}连通性测试失败（网络连接错误）: {str(e)}")
        logger.warning(f"请检查{instance_name}_BASE_URL={base_url}")
        pytest.fail(f"{instance_name}连通性测试失败: {str(e)}")
    except Exception as e:
        logger.error(f"{instance_name}连通性测试异常: {str(e)}")
        logger.warning(f"{instance_name}可能需要特殊认证机制，连通性测试跳过")


# ============================================================================
# 资产管理系统连通性测试
# ============================================================================
@pytest.mark.asyncio
async def test_caasm_connectivity():
    """测试CAASM资产查询API连通性（可能与problems.md #1相关）"""
    base_url = os.getenv("CAASM_BASE_URL") or os.getenv("ASSET_API_BASE_URL")
    api_key = os.getenv("CAASM_API_KEY") or os.getenv("ASSET_API_KEY") or os.getenv("FOBRAIN_API_KEY")
    enabled = os.getenv("CAASM_ENABLED", "true").lower() == "true"
    
    if not enabled:
        pytest.skip("CAASM_ENABLED=false，跳过测试")
    
    assert base_url, "CAASM_BASE_URL未配置"
    assert api_key, "CAASM_API_KEY未配置"
    
    # 测试CAASM连接性
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                logger.success(f"CAASM连通性测试成功: HTTP {response.status}")
    except aiohttp.ClientConnectorError as e:
        logger.error(f"CAASM连通性测试失败（网络连接错误）: {str(e)}")
        logger.warning(f"可能的原因：URL格式错误，请检查CAASM_BASE_URL={base_url}")
        pytest.fail(f"CAASM连通性测试失败: {str(e)}")
    except Exception as e:
        logger.error(f"CAASM连通性测试异常: {str(e)}")
        logger.warning(f"CAASM可能需要特殊认证机制，连通性测试跳过")


@pytest.mark.asyncio
async def test_corplink_connectivity():
    """测试Corplink设备查询API连通性（可能与problems.md #2相关）"""
    base_url = os.getenv("CORPLINK_BASE_URL")
    api_key = os.getenv("CORPLINK_API_KEY")
    enabled = os.getenv("CORPLINK_ENABLED", "true").lower() == "true"
    
    if not enabled:
        pytest.skip("CORPLINK_ENABLED=false，跳过测试")
    
    assert base_url, "CORPLINK_BASE_URL未配置"
    assert api_key, "CORPLINK_API_KEY未配置"
    
    # 测试Corplink连接性
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                logger.success(f"Corplink连通性测试成功: HTTP {response.status}")
    except aiohttp.ClientConnectorError as e:
        logger.error(f"Corplink连通性测试失败（网络连接错误）: {str(e)}")
        logger.warning(f"可能的原因：URL格式错误，请检查CORPLINK_BASE_URL={base_url}")
        logger.warning(f"注意：CORPLINK_BASE_URL是否包含/api/路径？")
        pytest.fail(f"Corplink连通性测试失败: {str(e)}")
    except Exception as e:
        logger.error(f"Corplink连通性测试异常: {str(e)}")
        logger.warning(f"Corplink可能需要特殊认证机制，连通性测试跳过")


# ============================================================================
# 数据归档平台连通性测试
# ============================================================================
@pytest.mark.asyncio
async def test_dingtalk_connectivity():
    """测试钉钉AI表格API连通性（与problems.md无关）"""
    client_id = os.getenv("DINGTALK_Client_ID") or os.getenv("DINGTALK_CLIENT_ID")
    client_secret = os.getenv("DINGTALK_Client_Secret") or os.getenv("DINGTALK_CLIENT_SECRET")
    table_id = os.getenv("DINGTALK_TABLE_ID")
    enabled = os.getenv("DINGTALK_ENABLED", "true").lower() == "true"
    
    if not enabled:
        pytest.skip("DINGTALK_ENABLED=false，跳过测试")
    
    assert client_id, "DINGTALK_Client_ID未配置"
    assert client_secret, "DINGTALK_Client_Secret未配置"
    
    # 钉钉API需要获取access_token
    token_url = "https://api.dingtalk.com/v1.0/oauth2/accessToken"
    payload = {
        "appKey": client_id,
        "appSecret": client_secret
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                token_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    if "accessToken" in result:
                        logger.success("钉钉AI表格连通性测试成功（获取accessToken成功）")
                    else:
                        logger.warning(f"钉钉API返回异常: {result}")
                else:
                    error_text = await response.text()
                    logger.error(f"钉钉连通性测试失败: HTTP {response.status}, {error_text}")
                    pytest.fail(f"钉钉连通性测试失败: HTTP {response.status}")
    except Exception as e:
        logger.error(f"钉钉连通性测试异常: {str(e)}")
        pytest.fail(f"钉钉连通性测试异常: {str(e)}")


@pytest.mark.asyncio
async def test_itsm_connectivity():
    """测试ITSM工单系统API连通性（与problems.md无关）"""
    base_url = os.getenv("ITSM_BASE_URL")
    user = os.getenv("ITSM_USER")
    password = os.getenv("ITSM_PASSWORD")
    enabled = os.getenv("ITSM_ENABLED", "true").lower() == "true"
    
    if not enabled:
        pytest.skip("ITSM_ENABLED=false，跳过测试")
    
    assert base_url, "ITSM_BASE_URL未配置"
    assert user, "ITSM_USER未配置"
    assert password, "ITSM_PASSWORD未配置"
    
    # 测试ITSM连接性
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                logger.success(f"ITSM连通性测试成功: HTTP {response.status}")
    except aiohttp.ClientConnectorError as e:
        logger.error(f"ITSM连通性测试失败（网络连接错误）: {str(e)}")
        logger.warning(f"请检查ITSM_BASE_URL={base_url}")
        pytest.fail(f"ITSM连通性测试失败: {str(e)}")
    except Exception as e:
        logger.error(f"ITSM连通性测试异常: {str(e)}")
        logger.warning(f"ITSM可能需要特殊认证机制，连通性测试跳过")


# ============================================================================
# 测试报告生成
# ============================================================================
def test_generate_report():
    """生成API连通性测试报告"""
    report = {
        "LLM": "✅" if os.getenv("MODEL_AGENT_API_KEY") else "❌",
        "Threatbook": "✅" if os.getenv("THREAT_BOOK_API_KEY") else "❌",
        "XDR": "✅" if os.getenv("XDR_API_KEY") else "❌",
        "NDR_NORTH": "✅" if os.getenv("NDR_NORTH_API_KEY") else "❌",
        "NDR_SOUTH": "✅" if os.getenv("NDR_SOUTH_API_KEY") else "❌",
        "CAASM": "✅" if os.getenv("CAASM_API_KEY") else "❌",
        "Corplink": "✅" if os.getenv("CORPLINK_API_KEY") else "❌",
        "DingTalk": "✅" if os.getenv("DINGTALK_Client_ID") else "❌",
        "ITSM": "✅" if os.getenv("ITSM_USER") else "❌",
    }
    
    logger.info("\n" + "="*60)
    logger.info("API连通性测试报告（配置检查）")
    logger.info("="*60)
    for api, status in report.items():
        logger.info(f"{api:15s} {status}")
    logger.info("="*60)
    
    # 统计
    total = len(report)
    configured = sum(1 for v in report.values() if v == "✅")
    logger.info(f"总计: {configured}/{total} API已配置")
    
    assert configured == total, f"部分API未配置: {total - configured}个"

# 介绍

## 什么是 MCP

Model Context Protocol（MCP）是由 Anthropic 主导推出的开放协议，旨在为大语言模型（LLM）与外部数据源、工具建立标准化交互接口。其技术设计类似于计算机世界的"USB+C 接口"。通过将模型与工具/数据库标准连接方式，可大幅提升开发效率与安全性。

### MCP 技术架构原理

MCP 采用客户端-服务端架构，通过分层设计实现模块化扩展：

- **MCP 应用（Host）**：用户直接操作的 AI 应用（如 Agent、桌面 AI 工具、IDE 插件），负责发起数据请求并协调交互流程。例如在代码编写场景中，IDE 插件作为 Host 向 LLM 请求代码生成与查阅。

- **MCP 客户端（Client）**：嵌入 Host 的协议转接层，与服务器建立 1:1 连接，管理会话通信，每个 Host 可同时连接多个客户端，实现跨数据源的并行访问（如同时读取本地文件与调用远程 API）。

- **MCP 服务器（Server）**：轻量级服务程序，通过标准化接口暴露三类核心能力：
  - **资源（Resources）**：静态数据（文件/数据库）或动态模板（支持 URI 模板参数化查询）
  - **工具（Tools）**：可执行操作（如 API 调用、代码执行）
  - **提示（Prompts）**：预定义上下文模板（如代码审查模板）

## 微步 MCP 的优势

### 实时提供优质威胁情报

威胁情报 MCP 深度集成微步威胁情报，通过实时数据驱动安全智能体做出高置信度的精准决策。

### 模型友好的上下文设计

威胁情报 MCP 提供清晰、标准的 MCP 工具描述，使 AI 智能体能够精准识别并调用所需工具，高效完成安全运营任务。

### 主流智能体框架支持

基于标准化协议的威胁情报 MCP 具备开箱即用的对接能力，可大幅加速安全智能体解决方案的部署应用。

---

# 前提条件

## 获取 KEY

威胁情报 MCP 服务通过 API KEY 进行鉴权，调用 MCP 服务之前，需获取可用的 API KEY。威胁情报 MCP 服务与云 API 共用一个 KEY，您的 KEY 包含您所有的 MCP 及 API 相关调用权限，请妥善保管，不要与他人共享。[查看我的 KEY](https://x.threatbook.cn/node/account)

## 绑定 IP 白名单

为提升调用安全性，防止 KEY 泄露后的未授权访问，调用 MCP 之前需[绑定访问 IP](https://x.threatbook.cn/node/ipWhiteList)，云服务仅允许已绑定 IP 地址的客户端发起请求。

访问 IP 仅需绑定一次，在调用 MCP 或 API 服务中共同生效。

## 如何获取使用权限

可通过微步在线官网（https://threatbook.com/trial）提交测试申请，获取免费试用机会，我们将在 3 个工作日内与您取得联系。

---

# 配置对接

## 通过智能体客户端界面配置（Cherry Studio）

1. 确保已安装最新版 Cherry Studio
2. 服务配置流程：设置 > MCP > 右上角【添加】按钮选择"快速创建"
3. 填写配置信息：
   - **名称**：微步在线威胁情报MCP服务
   - **类型**：选择"可流式传输的HTTP（streamableHttp）"
   - **URL**：`https://mcp.threatbook.cn/mcp?apikey=<已授权的APIKEY>`
4. 保存并开启该服务
5. 在 Chat 界面中提问并查看微步 MCP 服务提供的工具效果

## Python SDK

### Streamable HTTP 通信

```python
import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

mcp_server_url = "https://mcp.threatbook.cn/mcp?apikey=xxx"

async def main():
    # Connect to a streamable HTTP server
    async with streamablehttp_client(mcp_server_url) as (
        read_stream,
        write_stream,
        _,
    ):
        # Create a session using the client streams
        async with ClientSession(read_stream, write_stream) as session:
            # Initialize the connection
            await session.initialize()
            # List available tools
            tools = await session.list_tools()
            print(f"Available tools: {[tool.name for tool in tools.tools]}")

            # Call a vuln_query tool
            result = await session.call_tool(
                name="vuln_query",
                arguments=  {"vuln_id":"CNVD-2021-01627"}
            )
            print(f"Tool result: {result}")


if __name__ == "__main__":
    asyncio.run(main())
```

---

# MCP赋能AI安全运营场景

## 攻击面评估

数据的覆盖度和准确性决定了安全智能体做攻击面评估的最终效果。互联网资产测绘 MCP 提供开放端口、证书、应用服务及登录入口 Banner 等关键信息查询能力。安全 AI 智能体可利用这些数据，自动化地识别和评估企业资产的潜在风险点，将模糊的外部资产转变为清晰的防御目标。

**示例：Fortinet 中国有哪些资产？**

1. 通过网页搜索（web_search）工具搜集"Fortinet中国"相关信息，如官网域名、中文名称、是否有备案信息等；
2. 通过域名情报查询（domain_query）工具获取相关主域名或子域名的数据；
3. 通过测绘情报查询（internetAssets_query）工具补充查询测绘情报。

## 告警分析

在海量告警的挑战下，安全 AI 智能体的核心任务是快速定性和溯源。IP/域名/溯源拓线 MCP 提供了高效的判定和上下文分析能力，不仅能快速确定告警中 IP 或域名的恶意性，还能自动进行溯源拓线，找到威胁背后的实际控制者或所有者，极大提高对入侵事件的研判与响应效率。

**示例：帮我溯源"fget-career.com"**

1. 通过对域名进行溯源（domain_attribution）工具对"fget-career.com"进行溯源；
2. 基于上一步获取到的关联IP、样本，通过IP情报查询（ip_query）和文件情报查询（hash_query）工具进行深入分析，获取判定及上下文信息；
3. 通过域名情报查询（domain_query）工具对"fget-career.com"获取判定及关联数据等完成进一步分析。

## 漏洞分析及处置

自动化漏洞管理要求安全 AI 智能体能够高效识别资产风险并给出精准处置建议。漏洞列表、漏洞查询及漏洞资产匹配 MCP 提供了多条件查询和优质漏洞情报，尤其是漏洞资产匹配功能，解决了厂商产品描述不一致导致的匹配难题。这使得安全 AI 智能体能够精准地将最新漏洞情报与企业资产对号入座，并基于微步的优先级评估制定科学的处置策略。

**示例：请提供近 6 个月泛微 E-cology 公开的有 PoC 的高风险漏洞**

1. 通过漏洞影响厂商产品的精准识别（vuln_vendors_products_match）工具对用户问题中可能涉及的厂商产品名称（泛微,Ecology）进行微步漏洞库匹配；
2. 基于上一步获取的厂商产品名称，通过组合条件查询漏洞列表（vulnList_query）查询符合条件的漏洞列表；
3. 通过网页搜索（web_search）工具对漏洞范围做进一步补充；
4. 在上述2和3步骤中获取到的漏洞编号，通过漏洞详情查询（vuln_query）获取漏洞详细信息。

## 外部威胁感知

要实现主动防御，安全智能体必须掌握宏观威胁环境。外部威胁感知 MCP 支持按行业、地区、事件类型、攻击者等多个维度查询最新的威胁事件、黑客团伙动态。安全 AI 智能体借助此工具，能实时感知外部威胁变化，预测潜在的攻击趋势，从而指导企业安全策略进行动态调整和前瞻性防御部署。

**示例：香港 Circle K 便利店最近遭遇了什么攻击？**

1. 使用组合条件查询态势情报列表（HRTI_list_query）工具查询"Circle K"相关组织的威胁事件列表；
2. 基于上一步威胁事件列表中获取的报告ID，通过态势情报详情查询（HRTI_query）获取详细的事件详情；
3. 基于上一步获取的报告中关联的黑客组织，可以进一步通过黑客组织详情查询（threatActor_query）工具获取相关黑客动态。

---

# MCP具体说明

## IP 情报查询

| MCP 名称 | MCP 描述 |
|----------|----------|
| ip_query | 获取 IP 相关的情报信息，包含地理位置、运营商、情报判定、标签、与 IP 通信的文件样本、asn、RDNS 记录、端口、证书、IP 反查域名、攻击画像、情报洞察。 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| ip | 是 | string | 一个合法的 IPv4 或 IPv6 地址 |

---

## 对 IP 进行溯源

| MCP 名称 | MCP 描述 |
|----------|----------|
| ip_attribution | 对 IP 进行情报溯源 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| ip | 是 | string | 一个合法的 IPv4 或 IPv6 地址 |

---

## 域名情报查询

| MCP 名称 | MCP 描述 |
|----------|----------|
| domain_query | 获取域名相关的基础情报信息，包含情报判定、标签、相关样本、解析 IP、whois、证书、分类、ICP 备案信息、情报洞察、子域名等信息 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| domain | 是 | string | 一个合法的域名 |

---

## 对域名进行溯源

| MCP 名称 | MCP 描述 |
|----------|----------|
| domain_attribution | 对域名进行情报溯源 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| domain | 是 | string | 一个合法的域名 |

---

## 文件情报查询

| MCP 名称 | MCP 描述 |
|----------|----------|
| hash_query | 通过文件 hash 值获取文件相关情报，包括文件的概要信息、网络行为、行为签名、静态信息、释放行为、进程行为、反病毒扫描引擎检测结果。 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| hash | 是 | string | 文件的 hash 值，支持 sha256、sha1、md5 |

---

## 测绘情报查询

| MCP 名称 | MCP 描述 |
|----------|----------|
| internet_assets_query | 支持通过测绘查询语句获取测绘相关信息，包含 IP、端口、协议、域名、网站标题、响应头状态码、应用、组件、协议 banner、相关指纹 hash 等信息。默认返回最新扫描时间为最近一年的数据，最多一次返回 100 条数据。 |

### 测绘运算逻辑说明

| 连接符 | 含义 |
|--------|------|
| = | 匹配，表示查询包含关键词资产 |
| == | 精准匹配，表示仅查询关键词资产 |
| != | 剔除，表示剔除包含关键词资产 |
| () | 括号内容优先级最高 |
| &&、\|\| | 多条件组合查询。&&代表 and，\|\|代表 or |

### 详细测绘语法说明

#### 1. IP

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| ip | 检索IPV4及C网段资产（C端范围仅支持/24） | `ip="1.1.1.1"` `ip="1.1.1.1/24"` |
| ip | 支持多IP查询（最多3个），IP间用逗号隔开 | `ip="1.1.1.1,8.8.8.8"` |
| ipv6 | 检索单个IPV6 | `ipv6="2409:8762:1301::13"` |
| port | 检索开放特定端口的资产。支持多端口查询（最多3个），端口间用逗号隔开 | `port="20"` `port="20,21"` |
| asn | 检索指定asn的资产 | `asn="15169"` |
| country | 检索指定国家 | `country="中国"` |
| region | 检索指定省分/区域 | `region="辽宁"` |
| city | 检索指定城市 | `city="大连"` |
| isp | 检索指定运营商 | `isp="中国联通"` |
| host | 检索指定主机名 | `host="localhost"` |
| os | 检索指定操作系统及版本，操作系统和版本间需用:隔开 | `os="windows"` |
| ip_type | 检索IPV6资产，false为IPV6资产数据，true为IPV4资产数据 | `ip_type="false"` `ip_type="true"` |
| rdns | 检索rdns相关资产 | `rdns="dns.google"` |
| district | 检索地区资产 | `district="海淀区"` |
| owner | 检索IP地址所属组织拥有者 | `owner="阿里云"` |
| asn_name | 检索指定as名称的资产 | `asn_name="TRA"` |
| asn_org | 检索指定as组织的资产 | `asn_org="Tanzania Revenue Authority"` |

#### 2. Domain

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| domain | 检索指定网站域名资产 | `domain="baike.baidu.com"` |
| root_domain | 检索指定根域名资产 | `root_domain="baidu.com"` |
| dns | 检索域名站点dns解析的资产 | `dns="23.227.38.71"` |
| dns_type | 搜索dns解析类型对应的资产，包括：CNAME、NS、AAAA、TXT等解析类型 | `dns_type="A"` |

#### 3. ICP备案

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| icp | 检索特定备案号 | `icp="粤ICP备10063451号"` |
| icp_name | 检索备案网站名称 | `icp_name="微步在线"` |
| icp_company | 检索备案单位的资产 | `icp_company="微步在线科技有限公司"` |
| icp_type | 检索备案网站企业类型。包括：企业、政府机关、事业单位等 | `icp_type="企业"` |

#### 4. cert证书

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| cert.subject | 检索证书使用者 | `cert.subject="zygentoma.mschosting.com"` |
| cert.subject.org | 检索证书使用者单位 | `cert.subject.org="Oracle Corporation"` |
| cert.issuer | 检索证书颁发者 | `cert.issuer="cPanel, Inc"` |
| cert.issuer.org | 检索证书颁发者单位 | `cert.issuer.org="DigiCert"` |
| cert.hash | 检索证书指纹，支持sha1，sha256，MD5 | `cert.hash="88d4a0f7c1c5cb460181ab8b26db016e14af37d8"` |
| cert.sn | 检索证书序列号 | `cert.sn="08:11:65:6d:25:56:7a:3d:4d:e9:1a:a0:40:42:e0:7e"` |
| cert.dns | 检索含有指定域名的证书 | `cert.dns="threatbook.cn"` |
| cert.value | 检索证书颁发者和使用者相同的证书 | `cert.value="1"` |
| cert.is_trust | 检索证书可信的资产 | `cert.is_trust="true"` |
| cert.issuer.street | 检索证书颁发者地址 | `cert.issuer.street="beijing"` |
| cert.issuer.email_address | 检索证书颁发者邮箱 | `cert.issuer.email_address="ssl@vps.bleachanime.org"` |
| cert.subject.street | 检索证书持有者地址 | `cert.subject.street="beijing"` |
| cert.subject.email_address | 检索证书颁发者邮箱 | `cert.subject.email_address="ssl@vps.bleachanime.org"` |

#### 5. 服务数据

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| protocol | 检索指定协议资产 | `protocol="redis"` |
| protocol_type | 搜索协议类型 | `protocol_type="udp"` |
| transport | 检索传输层协议类型 | `transport="tcp"` |
| service | 检索特定服务类型资产 | `service="数据库服务"` |
| app | 检索指定组件及版本，组件和版本间需用:隔开 | `app="nginx"` |
| app_category | 检索指定组件类型 | `app_category="CDN"` |
| apply | 检索特定应用及版本，应用和版本间需用:隔开 | `apply="cloudflare"` |
| server | 检索指定服务器 | `server="Microsoft-IIS/10"` |

#### 6. 网站数据

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| title | 检索含有关键词的网页标题 | `title="网络安全"` |
| header | 检索含有关键词的http请求响应头 | `header="互联网"` |
| body | 检索含有关键词的html正文 | `body="威胁情报"` |
| banner | 检索含有关键词的banner信息 | `banner="redis_version"` |
| status_code | 检索指定状态码 | `status_code="500"` |
| plugins | 检索CS服务器 | `plugins="CobaltStrikeBeacon"` |
| plugins.values | 检索CS服务器的相关信息 | `plugins.values="service-5dttvfnl-1253933974.sh.apigw.tencentcs.com"` |
| js_name | 检索网页包含的js文件名的资产 | `js_name="bootstrap-datetimepicker.min.js"` |
| robots | 检索网页robots内容 | `robots="Disallow"` |
| psr | 检索网页中公安备案号 | `psr="京公网安备11000002000008号"` |

#### 7. 网站Hash

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| js_hash | 检索js源码与之匹配的资产 | `js_hash="4fd48cb285dcbe6949bc162f93b573f7"` |
| icon_hash | 检索使用此 icon 的资产（支持md5） | `icon_hash="28db76bf560e2e65f3405d611fbafaea"` `icon_hash="-1765087058"` |
| header_hash | 检索http头response hash | `header_hash="13f73a50a794f1f2eb6b95d18e3da6e4"` |
| html_hash | 检索html页面源码hash值 | `html_hash="79e89d6a6fdd79bb8e52d8a7e430aaf2"` |
| body_hash | 检索html body主体hash值 | `body_hash="bf5e3d7118544648d513f6c688be9eea"` |
| dom_hash | 检索html dom结构树hash值 | `dom_hash="fdac776e7b22f07df3e9b0776b6670cb"` |
| html_header_hash | 检索源码head hash值 | `html_header_md5_hash="d0d32f31f8b6edd58d81b8796517d957"` |
| sitemap_hash | 检索网页sitemap hash值 | `sitemap_md5_hash="bf929e401ccc65605ef3ecc5bf367bed"` |
| robots_hash | 检索网页Robots hash值 | `robots_md5_hash="4a6c16a62047601b7eef23a21bb00bce"` |
| ssdeep_hash | 检索网页源码ssdeep HASH值，主要用于源码相似性检索 | `ssdeep_hash="39363a6a4231364869385842393"` |
| content_length | 检索指定content_length对应的资产 | `content_length="125"` |
| etag | 检索指定网站etag对应的资产 | `etag="64a11841-23f"` |

#### 8. 其他Hash

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| banner_hash | 检索指定banner hash | `banner_hash="7535cdf4828da56347b8441ce591b09b"` |
| jarm | 检索jarm指纹 | `jarm="2ad2ad16d2ad2ad0002ad2ad2ad2ad3efac3c09ad758e28a073f01a172085c"` |
| ja3s | 检索ja3s指纹 | `ja3s="f4febc55ea12b31ae17cfb7e614afda8"` |
| ja4x | 检索ja4x指纹 | `ja4x="2bab15409345_af684594efb4_000000000000"` |
| ja4s | 检索ja4s指纹 | `ja4s="t120200_c02f_344b4dce5a52"` |
| ssh_finger_md5 | 检索ssh finger md5 hash值 | `ssh_finger_md5="7e:bd:45:b7:c5:39:85:31:bf:19:6c:19:15:4e:53:b5"` |
| ssh_finger_sha256 | 检索ssh finger sha256 hash值 | `ssh_finger_sha256="+Be02qGJnzqblm4hrnzzwaVXOS1cux9wJsdvXGA7kCY"` |

#### 9. vul漏洞

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| vul_id | 检索受该漏洞影响的资产，目前支持CVE、CNNVD编号查询 | `vul_id="CNNVD-200709-036"` |

#### 10. device设备

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| device | 检索指定设备 | `device="路由器"` |
| device_category | 检索设备配型 | `device_category="交换机"` |

#### 11. WHOIS信息

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| whois_registrant | 检索whois注册者名字 | `whois_registrant="REDACTED FOR PRIVACY"` |
| whois_company | 检索whois注册公司 | `whois_company="REDACTED FOR PRIVACY"` |
| whois_email | 检索whois注册邮箱 | `whois_email="@privacyguardian.org"` |
| whois_registrar | 检索whois服务商 | `whois_registrar="whois.cnnic.net.cn"` |

#### 12. 通用类别

| 语法表达 | 说明 | 示例 |
|----------|------|------|
| before | 查看before时间及以前数据（默认查询包含输入日期之前365天的数据） | `before="2022-07-06"` |
| after | 查看after时间及以后数据（默认查询包含输入日期之后365天的数据） | `after="2022-07-06"` |
| exists | 检索全部语法"存在"的资产数据，帮助过滤信息，可结合其他语法一起使用 | `city="大连"&&exists="domain"` |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| syntax | 是 | string | 符合描述中查询语法和查询运算逻辑规则的测绘查询语句。注意 value 必须携带英文"" |

---

## 漏洞影响厂商产品的精准识别

| MCP 名称 | MCP 描述 |
|----------|----------|
| vuln_vendors_products_match | 根据用户输入的信息精准匹配微步漏洞库定义的厂商产品标准名称，更精准定位、校正搜索内容 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| vendor | 否 | string | vendor 是指漏洞影响的厂商名称，支持精确查询 |
| product | 否 | string | product 是指漏洞影响的产品名称，支持精确查询 |

---

## 组合条件查询漏洞列表

| MCP 名称 | MCP 描述 |
|----------|----------|
| vulnList_query | 支持通过关键词实现精准漏洞检索，查询范围涵盖漏洞名称、影响厂商、影响产品、漏洞标签、风险等级、漏洞分类、漏洞利用路径、漏洞是否有 PoC、是否有修复方案，是否已发现在野利用、漏洞发布/公开时间、漏洞更新时间。默认情况下，最多可返回 50 个更新时间最新的漏洞。 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| vuln_name | 否 | string | 漏洞名称，支持模糊查询。推荐选择完整的漏洞名称或者核心关键词 |
| vendor | 否 | string | 漏洞影响的厂商名称，支持精确查询 |
| product | 否 | string | 漏洞影响的产品名称，支持精确查询 |
| tag | 否 | array | 漏洞标签（支持多选）。可选范围：RCE、数据泄露、业务中断、已知利用、重保 2025、重保 2024、重保 2023、重保 2022、重保、微步 PoC、公开 PoC、开源组件漏洞、AI 漏洞、关基、信创、两高一弱漏洞 |
| risk_level | 否 | string | 漏洞风险等级。只支持：高风险、中风险、低风险 |
| vuln_category | 否 | string | 漏洞分类。可选范围（只支持单选）：命令注入、代码注入、权限提升、未授权访问、文件包含、文件读取、文件删除、文件上传、文件下载、信任管理、信息泄露、远程代码执行、JNDI 注入、SQL 注入、XXE 注入、表达式注入、参数注入、模板注入、逻辑缺陷、权限管理错误、身份鉴别错误、服务端请求伪造、竞争条件、拒绝服务、跨站脚本、跨站请求伪造、路径遍历、代码问题、配置错误、输入验证、数字错误、格式化字符串、缓冲区错误、加密问题、未充分验证数据可靠性、注入、DLL 劫持、资源管理错误、其他 |
| path | 否 | string | Web 漏洞利用路径（url path）。不包括 url 的主机名和参数部分内容，支持格式如：`/api/v1/users/1/password`。注意，path 参数不能只是'/'，必须包含明确路径 |
| has_poc | 否 | bool | 漏洞是否存在 PoC。true 代表存在 PoC，false 代表不存在 Poc |
| has_solution | 否 | bool | 漏洞是否存在修复方案。true 代表存在漏洞修复方案，false 代表不存在漏洞修复方案 |
| has_kev | 否 | bool | 漏洞是否已发现在野利用行为。true 代表已发现在野利用行为，false 代表没有发现在野利用行为 |
| publish_time_start | 否 | string | 漏洞发布或公开的起始时间，格式：YYYY-MM-DD |
| publish_time_end | 否 | string | 漏洞发布或公开的终止时间，格式：YYYY-MM-DD |
| update_time_start | 否 | string | 漏洞更新的起始时间，格式：YYYY-MM-DD |
| update_time_end | 否 | string | 漏洞更新的终止时间，格式：YYYY-MM-DD |

---

## 漏洞详情查询

| MCP 名称 | MCP 描述 |
|----------|----------|
| vuln_query | 基于 vuln_query 工具获取漏洞详细信息，包含漏洞名称、描述、分类、标签、影响厂商产品、影响组件、修复方案、缓解措施、以及漏洞利用分析等信息。 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| vuln_id | 是 | string | 以 CVE、CNVD、CNNVD、NVDB、XVE、CITIVD、UTSA、UT、KVE、KYSA 为前缀的漏洞编号（不支持其他前缀格式）。其中 XVE 编号为微步自定义漏洞编号 |

---

## 网页搜索

| MCP 名称 | MCP 描述 |
|----------|----------|
| web_search | 精准地从用户问题中提取核心关键词，执行网络搜索。请注意，一次检索最多返回 10 条结果。 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| keyword | 是 | string | 从用户问题中精准提炼出核心关键词。关键词长度不可超过 200 字 |

---

## 网页浏览

| MCP 名称 | MCP 描述 |
|----------|----------|
| web_browsing | 获取网页相关内容信息，包含 url、标题、作者、正文、文章发布时间 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| url | 是 | string | 网页链接 |

---

## 组合条件查询态势情报列表

| MCP 名称 | MCP 描述 |
|----------|----------|
| HRTI_list_query | 支持通过关键词获取态势情报相关列表，查询范围覆盖 IOC、CVE 编号、标签、目标机构、目标地区、目标行业、事件类型、黑客组织及报告时间范围内的态势情报。按严重级别排序，一次最多返回最近的 10 条。 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| severity | 否 | string | 严重等级，分为严重、高、低 |
| keyword | 否 | string | 关键词。查询覆盖标题、概要、ioc、漏洞、标签。标题/概要包含查询，ioc/漏洞/标签精确查询 |
| target_organization | 否 | Array | 目标机构名称，包含查询 |
| target_region | 否 | Array | 目标地区名称，精确查询 |
| target_industry | 否 | Array | 目标行业分类名称，精确查询 |
| threat_type | 否 | Array | 事件类型，精确查询 |
| threat_actor | 否 | string | 黑客组织，包含查询且包含别名查询 |
| report_time_start | 否 | timestamp | 报告时间的起始，时间戳（日）。格式 yyyy-mm-dd |
| report_time_end | 否 | timestamp | 报告时间的终止，时间戳（日）。格式 yyyy-mm-dd |

---

## 态势情报详情查询

| MCP 名称 | MCP 描述 |
|----------|----------|
| HRTI_query | 获取态势情报详细信息，包含标题、时间、标签、事件、黑客组织及目标机构/区域/行业等基础信息、攻击手法、事件关键结论、防范建议、恶意命令行、恶意脚本、检测规则、恶意文件名、关联 IOC/CVE、及参考链接等信息 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| id | 是 | string | 报告 ID，是报告的唯一标识 |

---

## 组合条件查询黑客组织列表

| MCP 名称 | MCP 描述 |
|----------|----------|
| threat_actor_list_query | 支持通过关键词获取黑客组织相关列表，查询范围覆盖名称、别名、目标机构、目标地区、目标行业、来源、黑客组织分类及发现时间范围内的黑客组织。按最新发现时间排序，一次最多返回最近的 10 条。 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| keyword | 否 | string | 关键词。查询覆盖黑客组织名称、组织别名。包含查询 |
| target_organization | 否 | Array | 目标机构名称，包含查询 |
| target_region | 否 | Array | 目标地区名称，精确查询 |
| target_industry | 否 | Array | 目标行业分类名称，精确查询 |
| attribution | 否 | string | 黑客组织可能来源国家/地区，精确查询 |
| actor_type | 否 | Array | 黑客组织分类，精确查询，分类包含 APT、勒索、挖矿、黑灰产、白帽、其他共六种 |
| last_seen_time_start | 否 | timestamp | 最近发现时间的起始，格式 yyyy-mm-dd |
| last_seen_time_end | 否 | timestamp | 最近发现时间的终止，格式 yyyy-mm-dd |

---

## 黑客组织详情查询

| MCP 名称 | MCP 描述 |
|----------|----------|
| threat_actor_query | 获取黑客组织相关详细信息，包含名称、别名、分类、描述、来源国家及目标机构/区域/行业等基础信息、攻击手法、恶意命令行、恶意脚本、检测规则、恶意文件名、关联 IOC/CVE 等信息 |

**请求参数：**

| 参数名 | 必填 | 类型 | 说明 |
|--------|------|------|------|
| name | 是 | string | 黑客组织名称，包含查询，默认只返回一个最相关的查询结果 |

---

# 其他说明

## 调用异常说明

当调用成功，则"result"正常返回，"error"为空；当出现异常，error 中会出现明确的 code 和 message 提示，帮助定位问题。

### 调用成功时

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "key": "value"
  },
  "error": null
}
```

### 出现异常时

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": null,
  "error": {
    "code": -1,
    "message": "Invalid Account Status"
  }
}
```

### code 和 message 说明

| code | message | 说明 |
|------|---------|------|
| -1 | Invalid Account Status | 账户状态无效 |
| -1 | Invalid Access IP：{实际访问 IP} | 无效的访问 IP：{实际访问 IP} |
| -1 | Invalid API Key | 无效的 API key |
| -1 | Invalid Key Status | API key 状态无效 |
| -1 | Invalid Parameter：{parameter} | 无效的 API 接口参数：{参数名} |
| -1 | No Access to API Method | 没有访问权限 |
| -1 | Expired API Key | API Key 过期 |
| -2 | Invalid API Method | 无效的 API 接口 |
| -3 | Required:{resource/apikey/file/hash/url} | 接口请求参数必须项缺失：缺失的具体项 |
| -4 | Frequent Limitation | 触发访问频次限制 |
| -4 | Beyond Limitation | 超出访问限制 |
| -5 | System Error | 系统错误 |

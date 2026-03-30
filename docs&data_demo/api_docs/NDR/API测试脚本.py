import base64
import hmac
import requests
import time
import urllib.parse
from requests import exceptions

# 指定 ApiKey 和 Secret
api_key = "api-key"
secret = "secret"

# 指定请求 url路径 和 json 内容
# url="https://domain/api/v1/pcap/download"
url="https://domain/api/v1/log/searchBySql"
json={"time_from":1667750400,"time_to":1670342399,"sql":"(threat.level IN  ('attack','action'))","columns":[{"label":"类型","value":["threat.level","threat.result"]},{"label":"日期","value":"time"},{"label":"源","value":["net.src_ip","net.src_port"]},{"label":"目的","value":["net.dest_ip","net.dest_port"]},{"label":"协议","value":["net.type","net.http.method","net.http.status"]},{"label":"URL或域名","value":"data"},{"label":"威胁名称","value":"threat.name"},{"label":"ioc","value":"threat.ioc"},{"label":"is_connected","value":"threat.is_connected"}]}
headers={"Content-Type": "application/json;charset=UTF-8"}

# 文件上传参数，上传时headers不需要指定Content-Type
# files = {'file': open('./模板文件.csv', 'rb')}
# headers={}

# 获取当前时间戳
timestamp = int(time.time())

# 拼接需要签名的数据
sign_data = f"{api_key}{timestamp}"

# 计算 HmacSHA256 摘要
digest = hmac.new(secret.encode(), sign_data.encode(), "sha256").digest()

# 使用 Base64.encodeBase64URLSafeString 编码签名
signature = base64.urlsafe_b64encode(digest).rstrip(b"=")

def send_post_request(url, api_key, timestamp, signature, json=None, headers=None):
    """发送 POST 请求"""
    return requests.post(
        url, json=json, headers=headers, verify=False,
        # files=files,
        params={
            "api_key": api_key,
            "auth_timestamp": timestamp,
            "sign": signature,
        },
    )

def send_downloadPcap_request(url, api_key, timestamp, signature, headers=None):
    response = requests.get(
        url, params={
            "api_key": api_key,
            "auth_timestamp": timestamp,
            "sign": signature,
            "body": "{\"threat_id\":\"ckjmdmmhsfvdli486pi0\",\"src_ip\":\"10.2.2.1\",\"dest_ip\":\"10.2.2.11\",\"src_port\":49432,\"dest_port\":25,\"proto\":\"TCP\",\"occ_time\":1671538793,\"pos\":0,\"threat_type\":\"c2\",\"threat_name\":\"【自定义情报】auto_ip\",\"include_stream\":true}"
        }, headers = headers, stream=True
    )
    # 解析 Content-Disposition 字段
    content_disposition = response.headers.get('Content-Disposition')
    if content_disposition:
        # 从 Content-Disposition 字段中解析出文件名
        file_name = content_disposition.split('filename=')[1]
    else:
        # 如果没有 Content-Disposition 字段，则使用默认文件名
        file_name = 'TDP.pcap'
    file_name = urllib.parse.unquote(file_name)
    # 下载pcap文件到当前文件夹下
    with open(file_name.replace('"', ''), 'wb') as f:
        f.write(response.content)
    return response

if __name__ == '__main__':
    try:
        # 执行程序
        # 使用 requests 库调用 Java 接口
        response = send_post_request(url, api_key, timestamp, signature, json, headers)

        # pcap下载接口调用get方法
        # response = send_downloadPcap_request(url, api_key, timestamp, signature, headers)

        if response.status_code == 200:
            print("调用成功！")
            print(response.text)
    except exceptions.RequestException as e:
        print("调用失败: " + str(e))

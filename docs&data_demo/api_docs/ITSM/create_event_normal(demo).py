#!/usr/bin/env python
# 创建其它普通事件
import base64
import requests
import json

# 认证
login_url='https://itsmtest.longi.com:8443/developApi/itsmDevelopApi/user/loginCheckUser'
params = {
    "username": itsm_user(环境变量ITSM_user的值),
    "password": itsm_passrod(环境变量ITSM_passrod的值),
}
    # 编码
login_info=base64.b64encode(json.dumps(params).encode('utf-8')).decode('utf-8')
    # 构建参数
login_data={}
login_data["info"] = login_info

    # 打印login_info
print("login_data:",login_data)

# 登录认证
resp_data = requests.post(login_url,data=login_data)

# 获取token和key
data_text = resp_data.text
data_decode = base64.b64decode(data_text).decode('utf-8')
data_dict = json.loads(data_decode)
token = data_dict.get('rows').get('token')
key = data_dict.get('rows').get('key')
print("token:",token)
print("key:",key)

# 创建工单
create_url='https://itsmtest.longi.com:8443/developApi/itsmDevelopApi/itsmapi/flow_tran_api'

# 构建数据
from datetime import datetime as dt
data={
    "tran_key": "api_create_event",
    "cti": "68fca869c7814cdbbe9dff32ff0ab9ea",
    "title": f"其它标准事件工单测试-标题{dt.isoformat(dt.now())}",
    "request_userid": "387081",
    "flow_memo": f"应用系统类事件工单测试-正文{dt.isoformat(dt.now())}",
    "expect_time": "2025-12-29 10:00:10",
    "eventsource": "eventsource016",
    "app_id": "",
    "group_id": ""
}

files=[
    (
        'files_uploadfile',
        (
            'flow_id.lst',
            open('/root/flow_id.lst','rb'),
            'application/octet-stream'
        )
    )
]

    # 请求创建
# resp_data = requests.post(create_url, headers={"token":token}, data=data, files=files)
resp_data = requests.post(create_url, headers={"token":token}, data=data)
data_text = resp_data.text
data_decode = base64.b64decode(data_text).decode('utf-8')
data_dict = json.loads(data_decode)
print("result data:", data_dict)

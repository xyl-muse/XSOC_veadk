# 处置封禁

## 分组说明
本分组包含用于执行安全处置动作的API接口，包括自定义情报管理、旁路阻断、联动阻断、告警处置状态更新等。是安全运营的核心动作类接口。

## 业务意图
- **主要意图**: 执行安全处置、封禁威胁、更新处置状态
- **适用场景**: 应急响应、威胁处置、安全加固、情报管理
- **数据流向**: 写入操作，会修改系统状态

## 包含接口

| 接口 | 功能描述 | 操作类型 |
|------|---------|---------|
| custom/ioc/add | 添加自定义情报 | 写入 |
| custom/ioc/delete | 删除自定义情报 | 写入 |
| custom/ioc/list | 查询自定义情报列表 | 只读 |
| aside/block/add | 添加旁路阻断规则 | 写入 |
| aside/block/delete | 删除旁路阻断规则 | 写入 |
| aside/block/list | 查询旁路阻断列表 | 只读 |
| linkage/block/add | 添加联动阻断规则 | 写入 |
| linkage/block/delete | 删除联动阻断规则 | 写入 |
| linkage/block/list | 查询联动阻断列表 | 只读 |
| alert/disposal/status/update | 更新告警处置状态 | 写入 |

## AI使用指南

### 何时使用
- 用户请求"封禁IP"、"阻断威胁"、"添加情报"、"更新处置状态"
- 应急响应需要快速阻断时
- 管理威胁情报时

### ⚠️ 重要提醒
**本分组包含写入操作，执行前必须确认用户意图！**

### 调用前确认清单
```
1. 确认处置目标: IP/域名/主机是否正确？
2. 确认处置方式: 旁路阻断还是联动阻断？
3. 确认持续时间: 是否需要设置过期时间？
4. 评估影响范围: 是否会影响正常业务？
```

### 典型调用场景
```
场景1: 封禁恶意IP
- 选择阻断方式: aside_block 或 linkage_block
- 调用 xxx/add 接口
- 参数: ip, duration(可选), description(建议填写)

场景2: 添加威胁情报
- custom/ioc/add
- 参数: ioc_type(ip/domain/url/hash), ioc_value, threat_type

场景3: 更新告警状态
- alert/disposal/status/update
- 参数: alert_id, disposal_status(3=已处理)
```

### 注意事项
1. **必须确认用户意图后再执行写入操作**
2. 建议填写 description 参数记录处置原因
3. 阻断操作建议设置合理的过期时间
4. 删除操作不可逆，需谨慎执行

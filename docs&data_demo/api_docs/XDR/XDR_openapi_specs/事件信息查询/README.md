# 事件信息查询

## 分组说明
本分组包含用于查询安全事件信息的API接口，支持事件列表查询、GPT授权状态、事件趋势分析、事件实体信息获取等。

## 业务意图
- **主要意图**: 查询安全事件信息、获取事件关联实体
- **适用场景**: 事件调查、威胁分析、实体关联分析
- **数据流向**: 只读查询

## 包含接口

| 接口 | 方法 | 功能描述 |
|------|------|---------|
| /api/xdr/v1/incidents/gpt/isenabled | GET | GPT授权状态查询 |
| /api/xdr/v1/incidents/trends | POST | 事件趋势图统计 |
| /api/xdr/v1/incidents/list | POST | 查询安全事件列表 |
| /api/xdr/v1/incidents/{uuid}/entities/process | GET | 获取事件进程实体 |
| /api/xdr/v1/incidents/{uuid}/entities/file | GET | 获取事件文件实体 |
| /api/xdr/v1/incidents/{uuid}/entities/host | GET | 获取事件主机实体 |
| /api/xdr/v1/incidents/{uuid}/entities/ip | GET | 获取事件外网IP实体 |
| /api/xdr/v1/incidents/{uuid}/entities/innerip | GET | 获取事件内网IP实体 |
| /api/xdr/v1/incidents/{uuid}/entities/dns | GET | 获取事件DNS实体 |

## AI使用指南

### 何时使用
- 用户询问"安全事件"、"事件列表"、"事件实体"
- 需要查看事件关联的进程、文件、主机等实体时
- 分析事件趋势时

### 典型调用流程
```
1. 获取事件列表: incidents/list
2. 查看事件趋势: incidents/trends
3. 获取事件详情: incidents/{uuid}/proof
4. 获取关联实体:
   - 进程: entities/process
   - 文件: entities/file
   - 主机: entities/host
   - 外网IP: entities/ip
   - 内网IP: entities/innerip
   - DNS: entities/dns
```

### 注意事项
1. 实体查询需要提供有效的事件UUID
2. 不同类型实体返回不同的数据结构
3. 趋势图统计需要时间范围参数
4. GPT功能需确认授权状态后使用

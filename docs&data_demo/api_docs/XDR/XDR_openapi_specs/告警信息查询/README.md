# 告警信息查询

## 分组说明
本分组包含用于查询告警详细信息的API接口，支持IP信息聚合和告警列表查询。

## 业务意图
- **主要意图**: 查询告警详细信息、IP资产关联分析
- **适用场景**: 告警调查、资产关联分析、威胁定位
- **数据流向**: 只读查询

## 包含接口

| 接口 | 方法 | 功能描述 |
|------|------|---------|
| /api/xdr/v1/alerts/ipInfos | POST | IP信息聚合（支持源/目的IP分组） |
| /api/xdr/v1/alerts/list | POST | 查询安全告警列表（分页） |

## AI使用指南

### 何时使用
- 用户询问"告警列表"、"有哪些告警"、"IP相关告警"
- 需要查看具体告警详情时
- 进行IP与资产关联分析时

### 典型调用场景
```
场景1: 查询告警列表
- 调用 alerts/list 接口
- 参数: startTimestamp, endTimestamp, pageNum, pageSize

场景2: 源IP聚合分析
- 调用 ipInfos 接口
- 参数: aggBy=["srcIpInfos.ip"], limit=20

场景3: 目的IP资产分析
- 调用 ipInfos 接口
- 参数: aggBy=["dstIpInfos.assetId"], limit=20
```

### 注意事项
1. 列表查询支持分页，建议设置合理的 pageSize
2. IP聚合支持以 srcIpInfos 或 dstIpInfos 开头的分组字段
3. 可通过 filterParam 筛选特定条件的告警

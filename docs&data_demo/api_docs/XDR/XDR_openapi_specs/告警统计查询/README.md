# 告警统计查询

## 分组说明
本分组包含用于告警聚合统计的API接口，支持境内外攻击分析、攻击源与受攻击资产统计、多维度聚合查询等。

## 业务意图
- **主要意图**: 告警数据聚合统计、态势分析
- **适用场景**: 安全态势感知、大屏展示、报表统计、攻击趋势分析
- **数据流向**: 只读查询

## 包含接口

| 接口 | 方法 | 功能描述 |
|------|------|---------|
| /api/xdr/v1/alerts/branchstats | POST | 境内外受攻击资产查询统计 |
| /api/xdr/v1/alerts/ipinfosstats | POST | 告警攻击源与受攻击资产组统计 |
| /api/xdr/v1/alerts/aggregation | POST | 告警聚合通用API（支持多维度聚合） |

## AI使用指南

### 何时使用
- 用户询问"告警统计"、"攻击趋势"、"境内外攻击情况"
- 需要生成统计报表或态势大屏数据时
- 进行多维度告警分析时

### 典型调用场景
```
场景1: 境内外攻击分析
- 调用 branchstats 接口
- 参数: startTimestamp, endTimestamp, aggFuncs

场景2: 攻击源TOP分析
- 调用 ipinfosstats 接口
- 参数: aggBy=["srcIpInfos"], limit=10

场景3: 自定义聚合统计
- 调用 aggregation 接口
- 支持 filterParam 筛选、aggBy 分组、aggFuncs 聚合
```

### 注意事项
1. 必须传入时间范围 startTimestamp/endTimestamp
2. aggFuncs 定义聚合方式：count(统计)、cardinality(去重)
3. filterParam 支持多种筛选条件组合
4. 建议设置 limit 限制返回数量

# 事件统计查询

## 分组说明
本分组包含用于安全事件聚合统计的API接口，支持多维度事件数据聚合分析。

## 业务意图
- **主要意图**: 事件数据聚合统计、趋势分析
- **适用场景**: 态势大屏、统计报表、事件趋势分析
- **数据流向**: 只读查询

## 包含接口

| 接口 | 方法 | 功能描述 |
|------|------|---------|
| /api/xdr/v1/incidents/aggregation | POST | 事件聚合通用API |

## AI使用指南

### 何时使用
- 用户询问"事件统计"、"事件聚合"、"事件趋势"
- 需要进行多维度事件数据分析时
- 生成统计报表时

### 典型调用场景
```
场景: 自定义事件聚合统计
- 调用 incidents/aggregation 接口
- 参数:
  - startTimestamp/endTimestamp: 时间范围
  - aggBy: 分组字段
  - aggFuncs: 聚合函数
  - filterParam: 筛选条件
  - limit: 返回数量
```

### 聚合参数说明
- aggBy: 分组字段（如 severity、status 等）
- aggFuncs: 聚合操作
  - count: 计数
  - cardinalinality: 去重计数
- filterParam: 筛选条件
- sort: 排序方式
- limit: 返回数量限制

### 注意事项
1. 必须传入时间范围参数
2. 合理使用分组和聚合提高查询效率
3. 可组合多个聚合函数
4. 注意设置limit避免返回数据过多

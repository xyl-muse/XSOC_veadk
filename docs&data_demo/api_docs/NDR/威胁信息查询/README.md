# 威胁信息查询

## 分组说明
本分组包含用于查询威胁事件、告警主机、攻击事件详情等信息的API接口。是安全运营人员进行威胁分析的核心接口集合。

## 业务意图
- **主要意图**: 查询威胁事件、分析攻击行为、追踪攻击链
- **适用场景**: 威胁调查、告警分析、事件研判、攻击溯源
- **数据流向**: 只读查询，不修改系统状态

## 包含接口

| 接口 | 功能描述 |
|------|---------|
| alert/getSumList | 获取最新威胁事件聚合列表 |
| alert/search | 搜索告警详情 |
| host/getFallHostSumList | 获取告警主机列表 |
| host/threat/list | 获取主机关联的威胁事件列表 |
| incident/search | 搜索针对性攻击事件 |
| incident/topAttackedEntity | 获取事件TOP攻击实体 |
| incident/result | 获取事件攻击成功详情 |
| incident/timeline | 获取事件攻击时间线 |
| threat/inbound-attack/severity-distribution | 获取外部攻击严重性分布 |

## AI使用指南

### 何时使用
- 用户询问"告警情况"、"威胁事件"、"失陷主机"、"攻击详情"
- 需要进行威胁调查、分析攻击过程时

### 调用流程建议
```
1. 获取概览: alert/getSumList -> 了解整体威胁态势
2. 深入分析: host/getFallHostSumList -> 定位失陷主机
3. 追踪事件: incident/search -> 查询具体攻击事件
4. 分析过程: incident/timeline -> 获取攻击时间线
5. 获取详情: alert/search -> 查看告警详细信息
```

### 注意事项
1. 必须传入时间范围 `time_from`/`time_to`
2. `threat_characters` 参数用于筛选威胁性质，如 is_compromised(已失陷)、is_apt(APT)
3. 支持分页查询，建议使用合理的 `page_size`
4. 模糊查询使用 `fuzzy` 参数，包含 keyword 和 fieldlist

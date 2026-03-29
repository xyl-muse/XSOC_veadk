# 安全态势查询

## 分组说明
本分组包含用于获取整体安全态势、各类统计概览的Dashboard类API接口。适用于安全态势感知大屏、报表生成等场景。

## 业务意图
- **主要意图**: 获取安全态势概览、统计数据、趋势分析
- **适用场景**: 态势大屏、安全报表、日常监控、态势感知
- **数据流向**: 只读查询，不修改系统状态

## 包含接口

| 接口 | 功能描述 |
|------|---------|
| dashboard/status | 系统状态信息（Agent数、检测功能等） |
| dashboard/block | 阻断状态信息 |
| dashboard/security | 安全态势级别、失陷主机数 |
| dashboard/threaten_event | 威胁事件统计 |
| dashboard/threat-topic | 威胁专题（Webshell/挖矿/APT等） |
| dashboard/fileCheck | 威胁文件统计 |
| dashboard/phaseSum | 攻击链各阶段统计 |
| dashboard/loginApi | 登录入口风险统计 |
| dashboard/vulnerability | 脆弱性统计 |
| dashboard/track | 跟踪与狩猎信息 |
| dashboard/appFrame | Web应用和框架信息 |
| dashboard/unhandledHostList | TOP待处理主机列表 |
| dashboard/serviceClass | 服务分类统计 |
| dashboard/privacy-info | 敏感信息风险 |
| dashboard/alertLevelTrend | 告警趋势图 |

## AI使用指南

### 何时使用
- 用户询问"安全态势"、"整体情况"、"有什么风险"、"趋势如何"
- 需要获取Dashboard展示数据时
- 生成安全报表时

### 典型调用场景
```
场景1: 整体态势感知
- dashboard/status -> 系统运行状态
- dashboard/security -> 安全级别
- dashboard/threaten_event -> 威胁事件数

场景2: 威胁专题分析
- dashboard/threat-topic -> 各类威胁专题
- dashboard/fileCheck -> 威胁文件情况

场景3: 趋势分析
- dashboard/alertLevelTrend -> 告警趋势
```

### 注意事项
1. 多数接口需要传入时间范围参数
2. 返回数据为聚合统计，不是详细列表
3. 部分接口支持 `assets_group` 业务组筛选

# 安全告警查询

## 分组说明
本分组包含用于查询终端安全告警日志的API接口，涵盖安全基线检测、数据防泄漏(DLP)、防病毒等多种安全事件的告警日志查询。

## 业务意图
- **主要意图**: 查询终端安全告警日志
- **适用场景**: 安全审计、告警分析、事件调查、合规检查
- **数据流向**: 只读查询

## 包含接口

| 接口 | 方法 | 功能描述 |
|------|------|---------|
| /api/open/v1/security/baseline/events/list | GET | 获取终端安全基线告警日志 |
| /api/open/v1/security/edlp/events/list | GET | 获取数据防泄漏告警日志 |
| /api/open/v1/security/anti_virus/events/list | GET | 获取防病毒告警日志 |

## AI使用指南

### 何时使用
- 用户询问"安全告警"、"告警日志"、"安全事件"
- 需要查询特定类型的安全告警时
- 进行安全审计和合规检查时

### 典型调用场景

```
场景1: 查询基线告警
- 调用 security/baseline/events/list
- 参数: module=1(基线), level=3(高危)
- 用途: 检查系统配置安全问题

场景2: 查询数据泄露告警
- 调用 security/edlp/events/list
- 参数: file_type=1(纯文本), start_time, end_time
- 用途: 检查敏感数据外发情况

场景3: 查询病毒告警
- 调用 security/anti_virus/events/list
- 参数: os=windows
- 用途: 检查恶意软件感染情况

场景4: 查询特定设备的告警
- 所有接口都支持 did 参数
- 用途: 定位特定设备的安全问题
```

### 事件等级说明（baseline）
- 1: 低危
- 2: 中危
- 3: 高危

### 模块类型说明（baseline）
- 1: 基线检测
- 2: 软件检测
- 3: 进程检测

### 文件类型说明（edlp）
- 1: 纯文本
- 2: PDF
- 3: Word
- 4: Excel
- 5: PPT
- 6: 图片
- 7: 压缩包

### 处置动作说明（anti_virus）
- 1: 仅提醒
- 2: 提醒隔离可恢复
- 3: 提醒隔离不可恢复

### 注意事项
1. 各接口需要对应的接口权限
2. 时间参数使用Unix时间戳（秒）
3. 分页参数 limit 最大值 200
4. 用户ID格式为 ou_xxx
5. 设备ID格式为 did
6. 可通过 did 或 id（用户ID）定位特定设备或用户的告警

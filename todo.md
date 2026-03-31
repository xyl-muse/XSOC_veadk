# XSOC智能安全运营智能体系统开发TODO
## （基于VEADK框架 - 纯业务开发）
---
### 📌 开发规范依据：`rule.md`（VEADK官方开发指南，本项目所有开发严格遵循此规范）
---
## 整体开发进度
### Phase 0: 项目初始化 ✅（已完成）
- [x] VEADK标准项目结构搭建
- [x] 依赖配置（pyproject.toml）
- [x] 全局配置（veadk.yaml）
- [x] 项目入口（main.py 3行代码启动）
- [x] 环境变量模板（.env.example）
- [x] Dockerfile容器化配置
- [x] 标准化安全事件Schema定义（schemas/security_event.py）
---
### Phase 1: 专家智能体开发（预计5天）
#### 1.1 事件研判专家 ✅（已完成）
- [x] 完善自然语言解析能力（支持人工输入事件转换为标准格式）
- [x] 新增XDR多格式告警适配（支持扁平结构、state嵌套结构、Unix时间戳转换）
- [x] 增强SecurityEvent.from_input字段提取能力（适配uuId/hostIp/riskTag等XDR原生字段）
- [x] 优化研判规则与提示词（增加对riskTag/threatDefineName/gptResult等字段的利用）
- [x] 增加多源证据交叉验证逻辑
- [x] 实现误报规则库匹配（包含白名单、业务行为、高频告警等规则）
- [x] 单元测试编写（tests/unit/agents/test_investigation_agent.py，使用真实XDR告警样例）
- [x] 异步方法支持（将同步方法改为异步方法，提高并发处理能力）
#### 1.2 溯源分析专家智能体 ✅（已完成）
- [x] 智能体基础框架实现（继承VEADK Agent）
- [x] 溯源逻辑与攻击路径还原算法
- [x] 多工具调用编排策略
- [x] 溯源报告结构化生成
- [x] 循环溯源逻辑实现（发现新线索可回退到研判阶段）
- [x] 单元测试编写（tests/unit/agents/test_tracing_agent.py）
- [x] 异步方法支持（将同步方法改为异步方法，提高并发处理能力）
#### 1.3 风险处置专家智能体 ✅（已完成）
- [x] 智能体基础框架实现（继承VEADK Agent，启用enable_supervisor=True）
- [x] 最小影响处置策略生成（优先使用API封禁/白名单，其次考虑终端隔离）
- [x] 处置操作安全校验机制（检查IP是否属于内部网段、目标资产是否为核心业务系统）
- [x] 处置效果自动验证（检查封禁是否生效、终端是否隔离成功）
- [x] 处置失败回滚逻辑（执行失败时恢复到原始状态）
- [x] 处置动作实现（IP封禁、白名单管理、终端隔离、告警状态更新）
- [x] 操作服务器的动作必须经过人工审核（通过VEADK的HITL机制触发）
- [x] 单元测试编写（tests/unit/agents/test_response_agent.py）
- [x] 异步方法支持（将同步方法改为异步方法，提高并发处理能力）
#### 1.4 数据可视化专家智能体 ✅（已完成）
- [x] 智能体基础框架实现（继承VEADK Agent）
- [x] Markdown格式事件报告生成
- [x] XDR事件归档回写（基于XDR接口文档实现）
- [x] 钉钉AI表格数据同步（先按照网络接口实现，后续补充具体接口）
- [x] 事件数据标准化映射
- [x] 单元测试编写（tests/unit/agents/test_visualization_agent.py）
- [x] 异步方法支持（将同步方法改为异步方法，提高并发处理能力）
---
### Phase 2: 安全工具集开发（预计5天，**依赖docs/目录下的接口文档**）
> 📌 所有工具开发的唯一输入依据：`docs/`目录下对应的MCP/API接口说明文档，文档到位后才能启动开发
#### 2.0 前置任务：接口文档收集和接口分类 ✅ 已全部完成
- [x] XDR平台API接口文档放入docs&data_demo/api_docs/XDR/（JSON格式）
- [x] NDR平台API接口文档放入docs&data_demo/api_docs/NDR/（JSON格式）
- [x] Corplink平台API接口文档放入docs&data_demo/api_docs/corplink/（JSON格式）
- [x] 钉钉AI表格API接口文档放入docs&data_demo/api_docs/DingtalkAITable/ (txt格式)
- [x] 微步在线威胁情报MCP文档放入docs&data_demo/api_docs/ThreatbookMCP/ (md格式)
- [x] 云盘资产查询接口文档放入docs&data_demo/api_docs/CAASM/云盘资产查询/ (py示例)
- [x] CAASM资产管理系统(产品fobrain)接口文档放入docs&data_demo/api_docs/CAASM/Fobrain/ (json格式)
- [x] ITSM工单系统接口文档放入docs&data_demo/api_docs/ITSM/ (py示例+md)
- [x] 按照各个工具的接口细则信息，完成全平台101个接口的六大工具分类，输出《docs&data_demo/api_docs/接口分类清单.md》（原接口文档未动，分类清单作为工具开发唯一指导）
- [x] 根据主工具分类，完善2.1-2.6工具开发任务明细
#### 2.1 资产信息查询工具（依赖4平台接口，优先级：CAASM > Corplink > XDR > NDR）✅ 已完成
- [x] 实现CAASM云盘资产查询接口适配（服务器资产，1选优先）
- [x] 实现CAASM Fobrain资产列表查询接口适配
- [x] 实现Corplink设备信息查询接口适配（办公终端，1选优先）
- [x] 实现XDR风险资产查询/趋势查询接口适配（2选，资产数据少）
- [x] 实现NDR资产/域名/服务查询接口适配（3选，信息缺漏，最少使用）
- [x] 实现多平台资产信息合并逻辑，返回统一格式的资产数据
- [x] 支持参数：asset_ip(必填), platform(可选：caasm/corplink/xdr/ndr/all，默认all)
- [x] 单元测试编写（tests/unit/tools/test_asset_query.py，使用真实接口样例数据）

#### 2.2 攻击源威胁情报查询工具（依赖3平台接口，优先级：ThreatbookMCP > XDR > NDR）✅ 已完成
- [x] 实现ThreatbookMCP微步在线威胁情报查询接口适配（1选，必须优先查询）
- [x] 实现XDR攻击技术情报查询接口适配
- [x] 实现NDR攻击资产/威胁情报相关接口适配
- [x] 实现多平台威胁情报合并逻辑，返回统一格式的恶意判定结果（恶意标签、可信度、攻击类型、历史记录等）
- [x] 支持参数：ip/domain/hash(三选一必填), platform(可选：threatbook/xdr/ndr/all，默认all)
- [x] 单元测试编写（tests/unit/tools/test_threat_intel.py，使用真实威胁情报样例数据）

#### 2.3 事件信息查询工具（依赖2平台接口，优先级：XDR > NDR）✅ 已完成
- [x] 实现XDR平台11个事件相关接口适配（事件列表/趋势/实体/举证/统计等，1选，事件生产平台信息最全）
- [x] 实现NDR平台3个事件相关接口适配（事件结果/搜索/时间线，2选，根据告警情况使用）
- [x] 实现多平台事件信息合并逻辑，返回统一格式的事件详情
- [x] 支持参数：event_id(选填，查询单个事件)/event_ids(选填，批量查询)/start_time(选填)/end_time(选填)/platform(可选：xdr/ndr/all，默认all)
- [x] 单元测试编写（tests/unit/tools/test_event_query.py，使用真实XDR事件样例数据）

#### 2.4 告警及风险信息查询工具（依赖3平台接口，按需调用）✅ 已完成
- [x] 实现XDR平台9个告警/风险/日志相关接口适配
- [x] 实现NDR平台33个威胁/态势/风险/调查相关接口适配
- [x] 实现Corplink平台3个安全告警相关接口适配
- [x] 实现多平台告警风险信息合并逻辑，返回统一格式的告警数据
- [x] 支持参数：asset_ip(可选), time_range(可选，默认24h), alert_type(可选), severity(可选), platform(可选：xdr/ndr/corplink/all，默认all)
- [x] 单元测试编写（tests/unit/tools/test_alert_risk_query.py，使用真实告警样例数据）

#### 2.5 处置操作工具（依赖2平台接口，操作需安全校验）✅ 已完成
- [x] 实现XDR平台9个处置/白名单相关接口适配（告警处置状态更新/列表查询、事件处置状态更新/列表查询、白名单创建/删除/更新/列表查询/状态更新）
- [x] 实现NDR平台13个处置封禁/白名单相关接口适配（联动阻断添加/删除/列表、旁路阻断添加/删除/列表、自定义IOC添加/删除/列表、告警状态更新、白名单添加/删除/列表）
- [x] 实现操作安全校验逻辑（检查IP是否属于内部网段、目标资产是否为核心业务系统、风险级别分级：low/high/critical）
- [x] 实现操作结果验证逻辑（封禁验证、白名单验证）
- [x] 实现失败回滚逻辑（封禁回滚、白名单回滚）
- [x] 支持参数：action_type(必填：block/aside_block/linkage_block/unblock/whitelist/remove_whitelist/update_status), target(必填), target_type(ip/domain/alert/incident), duration(可选), platform(xdr/ndr/all), verify_result(默认True), auto_rollback(默认True)
- [x] 单元测试编写（tests/unit/tools/test_response_tool.py，47个测试用例全部通过，覆盖安全校验、XDR操作、NDR操作、主接口、查询函数、验证回滚、边界情况）

#### 2.6 数据归档工具（依赖3平台接口，全流程自动化）✅ 已完成
- [x] 实现XDR事件报告回写接口适配（HMAC-SHA256签名认证，/api/xdr/v1/appstoreapp/longjiln-event-to-agent/callback/incident）
- [x] 实现XDR事件/告警处置状态回写接口适配（复用response_tool逻辑）
- [x] 实现钉钉AI表格数据同步接口适配（OAuth2认证，insertNotableRecords）
- [x] 实现ITSM工单创建接口适配（Base64编码登录认证 + 工单创建API）
- [x] 支持参数：archive_type(xdr/xdr_status/dingtalk/itsm/all), event_id(必填), event_data(必填), target_type(alert/incident), deal_status, comment
- [x] 统一入口函数：data_archive()，支持并发执行多平台归档
- [x] 便捷函数：xdr_writeback(), dingtalk_sync(), itsm_create_ticket()
- [x] 单元测试编写（tests/unit/tools/test_data_archive_tool.py，31个测试用例全部通过）

#### 2.7 工具集整体集成测试
- [ ] 六大工具联动集成测试（tests/integration/test_tool_chain.py，验证工具调用链正确性）
- [ ] 工具参数校验与异常场景测试
- [ ] 多平台接口降级与容错测试
- [ ] 工具性能与并发测试
---
### Phase 3: 流程与规则开发（预计3天）
- [ ] 智能体协作流程定义（flows/security_event_flow.py）
- [ ] 事件状态机流转规则
- [ ] 错误回转与重试机制
- [ ] 熔断保护规则
- [ ] 人工干预流程实现
---
### Phase 4: 测试与上线（预计3天）
#### 4.1 测试用例开发
- [ ] 智能体单元测试
- [ ] 工具单元测试
- [ ] 全流程集成测试
- [ ] 异常场景测试
#### 4.2 部署与验证
- [ ] 开发环境联调
- [ ] 测试环境灰度验证
- [ ] 生产环境部署配置
- [ ] 运营监控配置
---
## 验收标准
1. **功能验收**
   - 4个专家智能体全流程自动化闭环处理
   - 9类安全工具集全部集成可用
   - 支持XDR API推送和人工录入双输入源
   - 事件全链路可追踪、可审计
2. **效果验收**
   - 误报识别准确率≥90%
   - 溯源分析准确率≥85%
   - 处置操作准确率≥99%
   - 单事件平均处理耗时≤30分钟

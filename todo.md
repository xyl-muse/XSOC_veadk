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
#### 2.0 前置任务：接口文档收集和接口分类
- [x] XDR平台API接口文档放入docs&data_demo/api_docs/XDR/（JSON格式）
- [x] NDR平台API接口文档放入docs&data_demo/api_docs/NDR/（JSON格式）
- [x] Corplink平台API接口文档放入docs&data_demo/api_docs/corplink/（JSON格式）
- [ ] 钉钉AI表格API接口文档放入docs&data_demo/api_docs/DingtalkAITable/
- [ ] 微步在线威胁情报API接口文档放入docs&data_demo/api_docs/ThreatbookMCP/
- [ ] CAASM资产管理系统接口文档放入docs&data_demo/api_docs/CAASM/
- [ ] 资产云盘数据文档放入docs&data_demo/api_docs/CAASM/
- [ ] ITSM工单系统接口文档放入docs&data_demo/api_docs/ITSM/
- [ ] 按照各个工具的接口细则信息，筛选它属于六大主工具的哪一类，复制到对应位置(原接口文档不要动)，用于后续主工具构建
- [ ] 根据主工具分类，完善todo2.2-2.7的子工具列举
#### 2.1 资产信息查询工具（依赖docs&data_demo/api_docs/XDR/资产信息查询和docs&data_demo/api_docs/corplink/资产信息查询）

#### 2.2 攻击源威胁情报查询工具（依赖docs&data_demo/api_docs/XDR/威胁情报查询和docs&data_demo/api_docs/ThreatbookMCP/）

#### 2.3 事件信息查询工具（依赖docs&data_demo/api_docs/XDR/事件信息查询和docs&data_demo/api_docs/XDR/事件详情查询）

#### 2.4 告警及风险信息查询工具（依赖docs&data_demo/api_docs/XDR/告警信息查询和docs&data_demo/api_docs/XDR/风险资产查询）

#### 2.5 处置操作工具（依赖docs&data_demo/api_docs/XDR/处置操作和docs&data_demo/api_docs/XDR/白名单管理）

#### 2.6 数据归档工具（依赖docs&data_demo/api_docs/XDR/事件信息查询和docs&data_demo/api_docs/DingtalkAITable/）

#### 2.7 工具单元测试
- [ ] 资产信息查询工具单元测试（tests/unit/tools/test_asset_query.py）
- [ ] 攻击源威胁情报查询工具单元测试（tests/unit/tools/test_threat_intel.py）
- [ ] 事件信息查询工具单元测试（tests/unit/tools/test_event_query.py）
- [ ] 告警及风险信息查询工具单元测试（tests/unit/tools/test_alert_risk_query.py）
- [ ] 处置操作工具单元测试（tests/unit/tools/test_response_tools.py）
- [ ] 数据归档工具单元测试（tests/unit/tools/test_data_archive.py）
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

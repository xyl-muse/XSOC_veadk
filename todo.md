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
#### 1.1 事件研判专家 ✅（框架已完成，待完善业务逻辑）
- [ ] 完善自然语言解析能力（支持人工输入事件转换为标准格式）
- [ ] 新增XDR多格式告警适配（支持扁平结构、state嵌套结构、Unix时间戳转换）
- [ ] 增强SecurityEvent.from_input字段提取能力（适配uuId/hostIp/riskTag等XDR原生字段）
- [ ] 优化研判规则与提示词（增加对riskTag/threatDefineName/gptResult等字段的利用）
- [ ] 增加多源证据交叉验证逻辑
- [ ] 实现误报规则库匹配
- [ ] 单元测试编写（tests/unit/agents/test_investigation_agent.py，使用真实XDR告警样例）
#### 1.2 溯源分析专家智能体
- [ ] 智能体基础框架实现（继承VEADK Agent）
- [ ] 溯源逻辑与攻击路径还原算法
- [ ] 多工具调用编排策略
- [ ] 溯源报告结构化生成
- [ ] 循环溯源逻辑实现（发现新线索可回退到研判阶段）
- [ ] 单元测试编写（tests/unit/agents/test_tracing_agent.py）
#### 1.3 风险处置专家智能体
- [ ] 智能体基础框架实现（继承VEADK Agent）
- [ ] 最小影响处置策略生成
- [ ] 处置操作安全校验机制
- [ ] 处置效果自动验证
- [ ] 处置失败回滚逻辑
- [ ] 单元测试编写（tests/unit/agents/test_response_agent.py）
#### 1.4 数据可视化专家智能体
- [ ] 智能体基础框架实现（继承VEADK Agent）
- [ ] Markdown格式事件报告生成
- [ ] XDR事件归档回写
- [ ] 钉钉AI表格数据同步
- [ ] 事件数据标准化映射
- [ ] 单元测试编写（tests/unit/agents/test_visualization_agent.py）
---
### Phase 2: 安全工具集开发（预计5天，**依赖docs/目录下的接口文档**）
> 📌 所有工具开发的唯一输入依据：`docs/`目录下对应的MCP/API接口说明文档，文档到位后才能启动开发
#### 2.0 前置任务：接口文档收集
- [ ] 微步在线威胁情报MCP接口文档放入docs/
- [ ] XDR平台API接口文档放入docs/
- [ ] 资产管理系统API接口文档放入docs/
- [ ] NDR平台API接口文档放入docs/
- [ ] EDR平台API接口文档放入docs/
- [ ] 钉钉开放平台API接口文档放入docs/
#### 2.1 已完成示例工具 ✅
- [x] 微步在线威胁情报查询工具（示例模板，待根据docs/文档替换为真实MCP实现）
#### 2.2 XDR API工具集（依赖docs/XDR接口文档.md）
- [ ] XDR事件查询工具
- [ ] XDR举证详情查询工具
- [ ] XDR事件归档回写工具
#### 2.3 资产查询工具集（依赖docs/资产API接口文档.md）
- [ ] 服务器资产信息查询工具
- [ ] 办公终端资产信息查询工具
#### 2.4 NDR/EDR API工具集（依赖docs/NDR接口文档.md、docs/EDR接口文档.md）
- [ ] NDR告警详情查询工具
- [ ] EDR告警详情查询工具
- [ ] NDR IP封禁工具
- [ ] EDR终端隔离工具
#### 2.5 钉钉API工具集（依赖docs/钉钉API接口文档.md）
- [ ] 钉钉消息通知工具
- [ ] 钉钉AI表格数据写入工具
#### 2.6 工具单元测试
- [ ] 微步威胁情报工具单元测试（tests/unit/tools/test_threat_intel_tool.py）
- [ ] XDR API工具集单元测试（tests/unit/tools/test_xdr_tools.py）
- [ ] 资产查询工具集单元测试（tests/unit/tools/test_asset_tools.py）
- [ ] NDR/EDR工具集单元测试（tests/unit/tools/test_ndr_edr_tools.py）
- [ ] 钉钉API工具集单元测试（tests/unit/tools/test_dingtalk_tools.py）
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

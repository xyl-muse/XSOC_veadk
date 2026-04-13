1.环境变量中定义：CAASM_BASE_URL=https://caasm.longi.com 
    实际的资产查询工具中写的caasm查询接口url有问题，这块出错需要再确认tool写的api对不对

2.CORPLINK_BASE_URL=https://feilian.longi.com:10443/api/  #{base_url}/open/v1/device/search，这里应该加api;
    corplink系统的url格式是/api/open/v1/user/batch_get_id，我们的代码里环境变量多数定义是只定义域名，目录在工具中加载，这块/api写在变量里面，有点出入
    规范的写法，要么所有的env都带齐目录写好url，要么所有env都不带目录
    本项目中规范应该是env都不带目录，因为某一个系统的接口url太多了，如果都写死在env，后面的工具集就没办法展开

---

## 测试中发现的问题（2026-04-11）

### 3. NDR_NORTH网络不可达
**问题描述**：
- API连通性测试失败：`test_ndr_north_connectivity`
- 错误类型：`aiohttp.ClientConnectorError`（网络连接错误）
- URL配置：`https://10.0.180.99`（已正确使用https协议）

**可能原因**：
- IP地址不可达（防火墙、VPN未连接）
- SSL证书问题（自签名证书）
- NDR服务未启动

**影响范围**：
- 不影响系统其他功能
- 仅影响集团北数据中心的NDR查询和处置

**解决方案**：
1. 确认网络连通性（检查防火墙、VPN）
2. 如无法连通，临时禁用该实例：`NDR_NORTH_ENABLED=false`
3. 仅使用NDR_SOUTH实例

**与原problems.md关系**：无关（非URL格式问题，是网络连通问题）

---

### 4. 测试用例需要更新（NDR多实例配置）
**问题描述**：
- 单元测试失败：24/124（主要在`test_response_tool.py`）
- 集成测试失败：9/80（主要在`test_tool_chain.py`）

**失败原因**：
- NDR多实例代码变更（新增`ndr_instances`配置结构）
- 测试用例仍使用旧版单实例NDR配置（`config["ndr"]`）

**影响范围**：
- 不影响实际功能
- 仅影响测试覆盖率统计

**解决方案**：
1. 更新测试用例以适配新配置结构：
   - 修改`test_response_tool.py`中的NDR配置读取逻辑
   - 修改其他相关测试文件
2. 目标：测试通过率达到95%以上

**示例修改**：
```python
# 旧版配置（测试用例中）
ndr_config = config["ndr"]

# 新版配置（代码中）
ndr_instances = config["ndr_instances"]
ndr_config = ndr_instances["ndr_north"]  # 或 ndr_south
```

**与原problems.md关系**：无关（是代码变更导致的测试维护问题）

---

## NDR多实例测试修复记录（2026-04-11）

### 5. 已完成修复
**工具代码修复**（`tools/response_tool.py`）：
- ✅ `query_block_list()` - 支持从ndr_instances获取第一个启用的实例
- ✅ `query_whitelist_list()` - 支持多NDR实例并发查询
- ✅ `query_custom_ioc_list()` - 支持从ndr_instances获取第一个启用的实例

**测试代码修复**（`tests/unit/tools/test_response_tool.py`）：
- ✅ 批量替换16处Mock配置（`"ndr"` → `"ndr_instances": {"ndr_south":`）
- ✅ 部分测试断言更新

**修复方法**：
```python
# 旧代码
ndr_config = config["ndr"]

# 新代码
ndr_instances = config.get("ndr_instances", {})
ndr_config = next((inst for inst in ndr_instances.values() if inst.get("enabled")), None)
if not ndr_config:
    return {"success": False, "error": "没有启用的NDR实例"}
```

### 6. 新发现的问题
**问题A：测试断言逻辑不兼容**
- **原因**：多实例架构变更导致返回结果格式变化
- **表现**：
  - 断言中 `result["platform_results"]["ndr"]` 访问失败（KeyError）
  - 平台标识从 `"ndr"` 变为 `"ndr_south"`/`"ndr_north"`
- **影响**：7个测试失败（`test_response_tool.py`）
- **示例错误**：
  ```python
  # 旧断言（失败）
  assert "缺少api_secret" in result["platform_results"]["ndr"]["error"]
  
  # 新断言（应该）
  assert "没有启用的NDR实例" in result["error"]
  ```
- **解决方案**：
  1. 更新断言逻辑，使用实例名称 `"ndr_south"`
  2. 或修改返回结果结构，保持向后兼容

**问题B：返回结果结构变更**
- **旧版**：`{"platform": "ndr", ...}`
- **新版**：`{"platform": "ndr_south", ...}`
- **影响**：所有涉及平台标识的断言（约15处）
- **解决方案**：
  1. 统一更新断言中的平台标识
  2. 或在代码中添加平台名称映射逻辑

**问题C：其他测试文件Mock配置未更新**
- **影响文件**：
  - `tests/unit/tools/test_alert_risk_query.py`
  - `tests/unit/tools/test_asset_query.py`
  - `tests/unit/tools/test_event_query.py`
  - `tests/unit/tools/test_threat_intel.py`
  - `tests/integration/test_tool_chain.py`
- **预计修改**：约30处Mock配置
- **解决方案**：批量替换策略

### 7. 待修复项
- [ ] `tests/unit/tools/test_response_tool.py` - 7个测试失败（断言逻辑）
- [ ] `tests/unit/tools/test_alert_risk_query.py` - Mock配置待更新
- [ ] `tests/unit/tools/test_asset_query.py` - Mock配置待更新
- [ ] `tests/unit/tools/test_event_query.py` - Mock配置待更新
- [ ] `tests/unit/tools/test_threat_intel.py` - Mock配置待更新
- [ ] `tests/integration/test_tool_chain.py` - Mock配置待更新
- **总计**：36个测试待修复

**当前测试通过率**：83%（178/214）
**目标测试通过率**：95%+

**修复优先级**：
1. 🔴 高：修复工具代码运行时错误（✅ 已完成）
2. 🟡 中：更新测试Mock配置（⚠️ 部分完成）
3. 🟢 低：调整测试断言逻辑（待处理）

---

## NDR多实例修复最终成果（2026-04-12）

### 8. 工具代码修复完成（✅ 100%）

**修复范围**：18处config["ndr"]访问已全部修复

**文件1：tools/response_tool.py（12处）**
- ✅ `_verify_block_result()` (L960-972)：从ndr_instances获取第一个启用实例
- ✅ `_verify_whitelist_result()` (L992-1018)：支持多NDR实例验证
- ✅ `_rollback_block()` (L1022-1035)：支持多实例回滚操作
- ✅ `_rollback_whitelist()` (L1038-1058)：支持多实例回滚操作

**文件2：tools/event_query_tool.py（3处）**
- ✅ `event_query()` (L94-140)：支持多NDR实例并发查询

**文件3：tools/threat_intel_tool.py（3处）**
- ✅ `threat_intel_query()` (L99-155)：支持多NDR实例并发查询

**验证结果**：
- 搜索`config["ndr"]`：0处（全部修复）
- 运行时KeyError风险：已消除

---

### 9. 测试修复遇到的技术障碍（PowerShell编码问题）

**问题**：使用PowerShell批量替换测试Mock配置导致文件编码错误

**表现**：
- 中文字符乱码（UTF-8 → Latin1）
- pytest报错：`SyntaxError: invalid non-printable character`
- 示例：`"测试"` → `"æµè¯"`

**原因**：
- PowerShell默认UTF-16编码
- `Set-Content`不支持UTF-8无BOM
- 与Python pytest期望编码不兼容

**影响**：6个测试文件需更新Mock配置

**解决方案**：
- 使用Python脚本（非PowerShell）批量替换
- 或手动逐个更新测试文件

---

## 10. 事件状态可视化问题（待解决）

**问题描述**：
所有智能体回复需要加上：事件状态机 + 事件数据结构展示

**影响范围**：
- SecurityEventOrchestrator
- InvestigationAgent
- TracingAgent
- ResponseAgent
- VisualizationAgent

**待实现**：
在每次智能体回复时，附加当前事件的状态信息和关键数据结构，让用户能够实时了解事件处理的进度和上下文。


## 11.threat_intel_query工具错拿受害ip去作为攻击者查询情报，情报查询工具我们取得是攻击者ip，这块需要修改。攻击者信息可以从输入中去找寻攻击者信息，如果没有，去event_query/alert_query查询，补全卷宗信息

## 12.event_query工具也有问题，事件查询，查询的事件id是："uuId" : "incident-02de74d0-7968-4ce6-a52d-5bdf6e620ca0"，错误识别到"alert-xxxx-xx"

## 13.除了threat_intel_query工具调用，其他工具似乎调用都失败了

## 14.研判智能体工作完后，发现是误报，需要转入到可视化智能体，做数据归档

---

## 15. VEADK框架兼容性问题（核心架构冲突）

### 问题描述

VEADK框架自0.5.6版本废弃Agent.run()方法，导致所有写在run()中的业务逻辑从未被执行。

**影响范围**：
- 状态机（15种状态流转）
- 熔断器（失败阈值控制）
- 回滚机制（处置失败回滚）
- HITL审批（人工审核流程）
- 安全事件数据结构流转
- 确定性智能体调度顺序

### 设计哲学冲突

| 维度 | VEADK框架设计 | XSOC业务需求 |
|------|---------------|--------------|
| 执行驱动 | LLM驱动 | 代码驱动 |
| 决策方式 | LLM不确定性决策 | 确定性流程 |
| Agent调度 | LLM决定调用谁 | 固定顺序调度 |
| run()方法 | 已废弃 | 需要执行 |

**冲突本质**：框架要求"LLM是大脑"，业务需要"代码是大脑"

### 方案对比

| 方案 | 描述 | 改动量 | 状态机 | 熔断器 | 回滚 | HITL | 调度控制 | Web展示 | 框架融合 |
|------|------|--------|--------|--------|------|------|----------|---------|----------|
| A. Plugin | 框架扩展点注入 | 中等 | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | 高 |
| B. instruction驱动 | 重写prompt | 较小 | ❌ | ❌ | ❌ | ❌ | ⚠️ | ✅ | 完全 |
| C. RunProcessor | 拦截事件流 | 中等 | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | 低 |
| D. 完全重构 | 拥抱LLM驱动 | 极大 | ❌需重写 | ❌需重写 | ❌需重写 | ❌需重写 | ✅ | ✅ | 完全 |
| E. 换框架 | LangGraph等 | 极大 | ✅需重构 | ✅需重构 | ✅需重构 | ✅需重构 | ✅ | ❌需开发 | 无 |

### 方案局限分析

**方案A (Plugin)**：
- ✅ 可以实现状态机、熔断器、回滚、HITL
- ❌ 无法控制Agent调度顺序（LLM决定调用谁）
- 局限：Plugin只能拦截，不能编排

**方案B (instruction驱动)**：
- ⚠️ 调度顺序依赖LLM理解instruction
- ❌ 状态机、熔断器等业务逻辑无法实现
- 局限：无法实现确定性业务流程

**方案C (RunProcessor)**：
- ✅ 可以完全控制执行流程
- ⚠️ 需要手动构造Event（Web展示）
- 局限：框架利用率低，本质是跳出框架

### 结论

这是**框架设计哲学与业务需求的根本性冲突**，无法通过单一方案完美解决。

**建议**：
1. 如果LLM研判能力重要 → 方案B + 接受不确定性
2. 如果确定性流程重要 → 方案C + 接受低框架利用
3. 如果两者都重要 → 方案E（换框架）
1.NDR设备和数据中心相关，考虑到大公司存在：多地多数据中心多NDR实例 情况，将NDR系统和相关工具逻辑设计为多实例结构

---

## 2. Google ADK Issue: Web UI Agent Discovery Returns Non-Agent Directories

**Issue Title**: `/list-apps` endpoint returns non-agent directories in Web UI (v1.29.0)

---

## 🔴 Required Information

**Describe the Bug:**

The `/list-apps` endpoint returns all subdirectories in the agents directory, regardless of whether they contain valid agent definitions. This causes the ADK Web UI to display non-agent directories (like `tools/`, `schemas/`, `tests/`) in the agent selector dropdown, resulting in a poor user experience.

**Steps to Reproduce:**

1. Create a project directory with the following structure:
```
my_project/
├── my_agent/
│   ├── __init__.py
│   └── agent.py       # valid agent with root_agent
├── utils/              # not an agent
├── data/               # not an agent
└── tmp/                # not an agent
```

2. Run `adk web .` from `my_project/`
3. Open the Web UI at http://127.0.0.1:8000
4. Observe the agent selector dropdown shows: `utils`, `data`, `tmp`, and `my_agent`
5. Select `utils` or other non-agent directory → Loading error occurs

**Expected Behavior:**

Only directories containing a valid agent definition (`root_agent.yaml`, `agent.py` with `root_agent`, or `__init__.py` with `root_agent`) should appear in the agent list.

**Observed Behavior:**

All non-hidden subdirectories are listed regardless of whether they contain an agent. Selecting a non-agent directory results in a loading error:
```
ValueError: No root_agent found for 'utils'. Searched in 'utils.agent.root_agent', 'utils.root_agent' and 'utils\root_agent.yaml'.
```

**Environment Details:**

- ADK Library Version: 1.29.0
- Desktop OS: Windows 10 (also affects macOS/Linux)
- Python Version: 3.10

**Model Information:**

- Are you using LiteLLM: N/A
- Which model is being used: N/A (issue is in agent discovery, not model interaction)

---

## 🟡 Optional Information

**Regression:**

No, this has been the behavior since `list_agents()` was introduced. PR #3430 added a `list_agents_detailed()` endpoint that filters properly, but the Web UI frontend never adopted it and still calls the plain `/list-apps` endpoint.

**Logs:**

N/A - no error on the backend, the non-agent directories are simply returned in the API response.

**Screenshots / Video:**

The Web UI dropdown shows non-agent directories alongside valid agents, causing confusion for users.

**Additional Context:**

**Root Cause:**
The issue is in `AgentLoader.list_agents()` which only filters by `os.path.isdir()`, hidden directory prefix, and `__pycache__`. It does not verify the directory contains a recognized agent structure.

**Current Implementation (v1.29.0):**
```python
# google/adk/cli/utils/agent_loader.py
def list_agents(self) -> list[str]:
    base_path = Path.cwd() / self.agents_dir
    agent_names = [
        x
        for x in os.listdir(base_path)
        if os.path.isdir(os.path.join(base_path, x))
        and not x.startswith(".")
        and x != "__pycache__"
    ]
    return agent_names  # Returns ALL directories

# google/adk/cli/adk_web_server.py
@app.get("/list-apps")
async def list_apps(
    detailed: bool = Query(
        default=False,  # ⚠️ Default is False
        description="Return detailed app information"
    )
):
  if detailed:
    return self.agent_loader.list_agents_detailed()  # ✅ Would filter
  return self.agent_loader.list_agents()  # ❌ Returns all directories
```

**The Problem:**
- Backend provides `detailed` parameter to filter invalid agents
- Default value is `False`
- Web UI frontend (pre-compiled Angular app) calls `/list-apps` without passing `?detailed=true`

**Proposed Solutions:**

1. **Change backend default to `True`** (Recommended):
   - Fixes issue for all users immediately
   - No frontend changes required
   - Backward compatible

2. **Update frontend to pass `detailed=true`**:
   - Requires frontend rebuild
   - More explicit control

**Impact on Multi-Agent Systems:**

Modern multi-agent architectures typically have:
- One orchestrator agent (root agent)
- Multiple sub-agents (implemented as modules/classes)
- Utility directories (tools, schemas, tests, etc.)

The current behavior creates friction for this common architecture pattern.

**Minimal Reproduction Code:**

```python
from pathlib import Path
from google.adk.cli.utils.agent_loader import AgentLoader
import tempfile

with tempfile.TemporaryDirectory() as tmp:
    # Create valid agent
    (Path(tmp) / "real_agent").mkdir()
    (Path(tmp) / "real_agent" / "__init__.py").write_text(
        "from google.adk.agents.base_agent import BaseAgent\n"
        "class A(BaseAgent):\n"
        "  def __init__(self): super().__init__(name='a')\n"
        "root_agent = A()"
    )
    
    # Create non-agent directory
    (Path(tmp) / "not_an_agent").mkdir()
    
    loader = AgentLoader(tmp)
    result = loader.list_agents()
    
    print(result)
    # Returns: ['not_an_agent', 'real_agent']
    # Expected: ['real_agent']
```

**How often has this issue occurred?:**

- Always (100%)

---

## 3. VeADK Issue: Web UI 智能体发现显示非智能体目录

**Issue Title**: Web UI 智能体发现机制显示非智能体目录（继承自 Google ADK）

---

## 🔴 必填信息

**描述 Bug:**

VeADK 继承了 Google ADK 的 Web UI 智能体发现机制，该机制会在智能体选择下拉列表中显示所有子目录，包括非智能体目录（如 `tools/`、`schemas/`、`tests/` 等），导致用户界面混乱和不良的开发体验。

**复现步骤:**

1. 创建一个典型的 VeADK 多智能体项目结构：
```
xsoc_agent/
├── agent.py            # 根智能体
├── __init__.py
├── flows/              # ✅ 有效智能体 (SecurityEventOrchestrator)
│   ├── __init__.py
│   └── security_event_flow.py
├── agents/             # ❌ 非智能体 (子智能体代码)
├── tools/              # ❌ 非智能体 (工具模块)
├── schemas/            # ❌ 非智能体 (Pydantic模型)
└── tests/              # ❌ 非智能体 (单元测试)
```

2. 运行 `veadk web`
3. 打开浏览器访问 http://127.0.0.1:8000
4. 观察智能体选择下拉列表显示：`agents`, `flows`, `schemas`, `tests`, `tools`
5. 尝试选择 `agents` 或 `tools` 等目录 → 出现加载错误

**期望行为:**

下拉列表应仅显示包含有效智能体定义的目录（本例中应只显示 `flows`）。

**实际行为:**

Web UI 显示了所有子目录，选择非智能体目录时出现错误：
```
ValueError: No root_agent found for 'tools'.
```

**环境详情:**

- VeADK 版本: 0.5.29
- Google ADK 版本: 1.29.0
- 操作系统: Windows 10 / Linux / macOS
- Python 版本: 3.10+

**模型信息:**

- 是否使用 LiteLLM: N/A
- 使用的模型: N/A（问题出在智能体发现机制，与模型无关）

---

## 🟡 可选信息

**回归测试:**

这不是回归问题，而是从依赖的上游项目（Google ADK）继承的设计问题。相关 Issue：Google ADK #4647, #3429。

**日志:**

无后端错误日志。问题在于 `/list-apps` API 返回了所有目录名。

**截图 / 视频:**

Web UI 下拉列表中混入了非智能体目录，造成用户困惑。

**补充背景:**

**VeADK 与 Google ADK 的依赖关系:**
```
veadk-python (0.5.29)
    ↓ 依赖于
google-adk (>=1.19.0)
    ↓ 调用
google.adk.cli.cli_tools_click.cli_web()
```

**VeADK 的 cli_web.py 实现:**
```python
from google.adk.cli.cli_tools_click import cli_web

# VeADK 对 AdkWebServer 进行了一些 patch
# 但没有修改 list_apps 的行为
cli_web.main(args=extra_args, standalone_mode=False)
```

**根本原因:**
1. Google ADK 的 `/list-apps` 端点默认 `detailed=False`
2. 预编译的 Angular 前端硬编码了 API 调用，未传递 `?detailed=true`
3. VeADK 完全委托给 Google ADK，没有覆盖或 patch 这个行为

**对中国开发者的影响:**

VeADK 主要面向中国市场，用户构建企业级多智能体系统时面临：
- **界面混乱**: 看到 6+ 个选项，但只有 1-2 个有效
- **开发体验差**: 需要反复尝试才能找到有效智能体
- **生产部署问题**: 无效的智能体名称出现在部署场景中

**建议解决方案:**

**方案 1: 等待 Google ADK 修复（推荐）**

跟踪 Google ADK Issue #4647 的进展，等待上游修复后更新依赖。

优点：
- 无需修改代码
- 受益于整个 Google ADK 生态系统
- 保持与上游对齐

缺点：
- 依赖 Google ADK 发布时间线
- 期间用户仍会遇到此问题

**方案 2: 在 VeADK 层面临时 Patch**

在 `veadk/cli/cli_web.py` 中添加 monkey patch 强制使用 detailed 模式。

优点：
- VeADK 用户立即受益
- 不依赖上游时间线

缺点：
- 增加维护负担
- 可能与未来 Google ADK 版本产生兼容性问题
- Monkey patch 不够优雅

**方案 3: 文档说明**

在 VeADK 文档中说明当前行为和临时解决方案。

**最小复现代码:**

```python
# 创建测试项目结构
import tempfile
from pathlib import Path

with tempfile.TemporaryDirectory() as tmp:
    # 创建有效智能体
    (Path(tmp) / "flows").mkdir()
    (Path(tmp) / "flows" / "__init__.py").write_text(
        "from veadk import Agent\n"
        "root_agent = Agent(name='test', model='gemini-2.0-flash-exp')"
    )
    
    # 创建非智能体目录
    (Path(tmp) / "tools").mkdir()
    (Path(tmp) / "schemas").mkdir()
    
    # 运行 veadk web tmp
    # 下拉列表会显示: flows, schemas, tools
    # 但只有 flows 可用
```

**问题发生频率:**

- 总是 (100%)
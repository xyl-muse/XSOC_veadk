"""
XSOC安全运营智能体 - Python包入口文件

作用：
1. 作为Python包的入口点，支持被其他项目导入使用
2. 明确标识项目的根智能体定义位置

VeADK Web启动说明：
- `ve web` 命令通过扫描子目录来发现agent（AgentLoader.list_agents()）
- 本项目通过 flows/__init__.py 导出root_agent，符合AgentLoader的模式c）
- 根目录的agent.py不会被ve web扫描，但flows/会被识别为有效的agent
- 启动后在Web界面选择"flows"即可使用

项目架构：
- 编排agent（SecurityEventOrchestrator）定义在 flows/security_event_flow.py
- 负责协调4个子智能体：investigation、tracing、response、visualization
"""
from flows.security_event_flow import root_agent

__all__ = ['root_agent']

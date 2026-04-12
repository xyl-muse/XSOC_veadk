"""
XSOC安全运营智能体系统

VeADK框架要求：
- 根目录必须有__init__.py文件
- 必须包含 `from . import agent` 语句

这是VeADK模块化导出机制的一部分，确保：
- ve web命令能正确加载agent模块
- ve deploy命令能正确部署项目
"""
from . import agent

__all__ = ['agent']

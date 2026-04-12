# -*- coding: utf-8 -*-
"""
XSOC安全运营智能体系统入口

启动方式（VeADK 0.5.29+）：
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

【方式1】Web服务（推荐）
  启动命令: veadk web
  访问地址: http://localhost:8000
  可选参数:
    - 改变端口: veadk web --port 8888
    - 外部访问: veadk web --host 0.0.0.0
    - 调试模式: veadk web --log_level DEBUG

【方式2】命令行测试
  python main.py --test

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

说明：
- 新版VeADK已废弃VEADKApp类
- Web服务必须通过 'veadk web' 命令启动
- 项目已创建 agent.py 和 __init__.py 以符合VeADK规范
"""

import sys

if __name__ == "__main__":
    if "--test" in sys.argv:
        print("\n运行命令行测试...")
        print("提示：命令行测试功能待实现，建议使用 Web 服务进行测试：veadk web")
    else:
        print(__doc__)

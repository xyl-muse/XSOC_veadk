"""XSOC安全运营智能体系统入口"""
from veadk import VEADKApp

# 初始化VEADK应用，自动加载agents、tools、flows目录下的所有内容
app = VEADKApp(
    name="xsoc-security-agent",
    description="智能安全运营多智能体系统，实现安全事件自动化研判、溯源、处置全闭环"
)

if __name__ == "__main__":
    # 启动服务，默认端口8888，自带Web管理页面、API文档、监控面板
    app.run(host="0.0.0.0", port=8888, debug=True)

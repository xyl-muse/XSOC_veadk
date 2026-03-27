# VEADK标准Docker镜像
FROM python:3.10-slim-bookworm

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    git \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件
COPY pyproject.toml .
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir .

# 复制项目代码
COPY . .

# 暴露端口
EXPOSE 8888
EXPOSE 9090

# 设置环境变量
ENV PYTHONPATH=/app
ENV ENVIRONMENT=production

# 启动命令
CMD ["python", "main.py"]

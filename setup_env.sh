#!/bin/bash
# RSTP测试环境安装脚本 for Ubuntu

set -e

echo "========================================="
echo "RSTP自动化测试环境配置"
echo "========================================="

# 检测操作系统
if [ -f /etc/debian_version ]; then
    echo "检测到Debian/Ubuntu系统"
    PKG_MANAGER="apt-get"
else
    echo "警告：此脚本针对Debian/Ubuntu优化"
    exit 1
fi

# 更新包管理器
echo "更新软件包列表..."
sudo $PKG_MANAGER update

# 安装系统依赖
echo "安装系统依赖..."
sudo $PKG_MANAGER install -y \
    bridge-utils \
    iproute2 \
    tcpdump \
    iperf3 \
    python3 \
    python3-pip \
    build-essential \
    libssl-dev \
    libffi-dev

# 安装RSTP支持（mstpd）
echo "检查mstpd是否已安装..."
if command -v mstpd >/dev/null 2>&1 && systemctl is-active --quiet mstpd; then
    echo "✓ mstpd 已安装并正在运行，跳过安装"
else
    echo "安装并启动mstpd..."
    sudo $PKG_MANAGER install -y mstpd
    sudo systemctl enable mstpd 2>/dev/null || true
    sudo systemctl start mstpd 2>/dev/null || true
fi

# 安装Python依赖（直接使用系统环境）
echo "安装Python依赖..."
pip3 install -r requirement.txt --break-system-packages

# 创建必要的目录
echo "创建工作目录..."
mkdir -p logs reports temp

# 验证安装
echo ""
echo "========================================="
echo "验证安装..."
echo "========================================="

# 检查工具
for tool in brctl ip tcpdump iperf3 mstpctl; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool 已安装"
    else
        echo "✗ $tool 未找到"
    fi
done

# 检查Python包
echo ""
echo "Python包状态："
pip3 list | grep -E "pytest|paramiko|scapy"

echo ""
echo "========================================="
echo "安装完成！"
echo ""
echo "使用方法："
echo "运行测试: python3 run_tests.py"
echo "========================================="

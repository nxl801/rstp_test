#!/bin/bash
# DUT设备OVS环境安装脚本 for Ubuntu

set -e

echo "========================================="
echo "DUT设备OVS环境配置"
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

# 安装OVS
echo "检查OVS是否已安装..."
if command -v ovs-vsctl >/dev/null 2>&1 && systemctl is-active --quiet openvswitch-switch; then
    echo "✓ OVS 已安装并正在运行，跳过安装"
else
    echo "安装并启动OVS..."
    sudo $PKG_MANAGER install -y openvswitch-switch openvswitch-common
    sudo systemctl enable openvswitch-switch 2>/dev/null || true
    sudo systemctl start openvswitch-switch 2>/dev/null || true
    
    # 等待OVS服务完全启动
    echo "等待OVS服务启动..."
    sleep 3
fi

# 验证OVS数据库连接
echo "验证OVS数据库连接..."
for i in {1..10}; do
    if ovs-vsctl show >/dev/null 2>&1; then
        echo "✓ OVS数据库连接正常"
        break
    else
        echo "等待OVS数据库启动... ($i/10)"
        sleep 2
    fi
    if [ $i -eq 10 ]; then
        echo "✗ OVS数据库连接失败，请检查服务状态"
        exit 1
    fi
done

# 配置OVS基本设置
echo "配置OVS基本设置..."
# 确保OVS数据库配置正确
sudo ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=false

# 安装Python依赖（如果需要）
if [ -f "requirement.txt" ]; then
    echo "安装Python依赖..."
    pip3 install -r requirement.txt --break-system-packages
fi

# 创建必要的目录
echo "创建工作目录..."
mkdir -p logs reports temp

# 验证安装
echo ""
echo "========================================="
echo "验证安装..."
echo "========================================="

# 检查基本工具
for tool in brctl ip tcpdump iperf3; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool 已安装"
    else
        echo "✗ $tool 未找到"
    fi
done

# 检查OVS工具
echo ""
echo "OVS工具状态："
for tool in ovs-vsctl ovs-appctl ovs-ofctl; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool 已安装"
    else
        echo "✗ $tool 未找到"
    fi
done

# 检查OVS服务状态
echo ""
echo "OVS服务状态："
if systemctl is-active --quiet openvswitch-switch; then
    echo "✓ openvswitch-switch 服务正在运行"
else
    echo "✗ openvswitch-switch 服务未运行"
fi

# 测试OVS功能
echo ""
echo "测试OVS基本功能："
if ovs-vsctl show >/dev/null 2>&1; then
    echo "✓ OVS数据库连接正常"
    echo "当前OVS配置："
    ovs-vsctl show
else
    echo "✗ OVS数据库连接失败"
fi

# 检查Python包（如果存在requirement.txt）
if [ -f "requirement.txt" ]; then
    echo ""
    echo "Python包状态："
    pip3 list | grep -E "pytest|paramiko|scapy" || echo "Python包未安装或未找到"
fi

echo ""
echo "========================================="
echo "DUT环境安装完成！"
echo ""
echo "重要提示："
echo "1. 确保网络接口已正确配置"
echo "2. 测试接口(eth1/eth2)应保持UP状态但不分配IP"
echo "3. 管理接口应配置为可从宿主机访问的IP"
echo ""
echo "验证命令："
echo "  ovs-vsctl show                    # 查看OVS配置"
echo "  systemctl status openvswitch-switch  # 检查服务状态"
echo "  ovs-appctl version                # 查看OVS版本"
echo "========================================="
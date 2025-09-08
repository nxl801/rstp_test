#!/bin/bash
# 自动开启 root+密码 SSH 登录（仅适用于 Ubuntu/Debian）
# ⚠ 安全风险极高，请仅在内网测试环境使用！！

set -e

echo "=== [1/4] 设置 root 密码 ==="
echo "root:1" | chpasswd

echo "=== [2/4] 修改 ssh 配置 ==="
SSHD_CONFIG="/etc/ssh/sshd_config"

# 先备份
cp -a $SSHD_CONFIG ${SSHD_CONFIG}.bak.$(date +%s)

# 修改 PermitRootLogin
if grep -q "^#*PermitRootLogin" $SSHD_CONFIG; then
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' $SSHD_CONFIG
else
    echo "PermitRootLogin yes" >> $SSHD_CONFIG
fi

# 修改 PasswordAuthentication
if grep -q "^#*PasswordAuthentication" $SSHD_CONFIG; then
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' $SSHD_CONFIG
else
    echo "PasswordAuthentication yes" >> $SSHD_CONFIG
fi

echo "=== [3/4] 重启 SSH 服务 ==="
systemctl restart ssh || systemctl restart sshd

echo "=== [4/4] 检查服务状态 ==="
if systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1; then
    echo "✅ SSH 服务已开启 (root/1 登录已允许)"
else
    echo "❌ SSH 服务启动失败，请检查配置！"
fi

echo "提示：现在可以用 root 用户通过 SSH 登录，比如："
echo "  ssh root@<IP地址>"
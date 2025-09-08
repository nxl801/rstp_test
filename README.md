## 使用说明

1. **安装环境**：
```bash
chmod +x setup_env.sh
./setup_env.sh
```

2. **配置测试环境**：
编辑 `config.yaml` 文件，设置正确的VM路径和网络配置

**注意**：当前框架仅支持两个网口的RSTP功能测试，配置中只需要DUT和两个TestNode（TestNode1和TestNode2）。

3. **运行测试**：
```bash
# 激活虚拟环境
source venv/bin/activate

# 运行所有测试
python run_tests.py

# 只运行协议一致性测试
python run_tests.py -m protocol_conformance

# 详细输出
python run_tests.py --verbose

# 并行运行
python run_tests.py --parallel 4
```

4. **查看报告**：
- HTML报告: `reports/report_*.html`
- JUnit XML: `reports/junit_*.xml`
- 日志文件: `logs/test_*.log`

这个框架提供了完整的RSTP自动化测试能力，采用了pytest的最佳实践，具有良好的可扩展性和维护性。

## 拓扑支持

当前框架支持以下拓扑类型：
- **环形拓扑（RING）**：适用于两网口DUT设备的冗余路径测试
- **星形拓扑（STAR）**：适用于集中式网络测试
- **线性拓扑（LINEAR）**：适用于简单链路测试

**限制**：由于DUT设备只支持两个网口的RSTP功能，框架不再支持需要三个或更多节点的复杂网状拓扑测试。
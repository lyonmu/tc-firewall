# tc-firewall

> Go 语言实现的基于 eBPF TC 的防火墙

## 功能特性

- **eBPF TC 过滤**: 使用 Linux TC (Traffic Control) 框架在网络接口 ingress 方向过滤数据包
- **高性能**: eBPF 程序在内核态执行，无用户态数据包转发开销
- **多协议支持**: 支持 TCP 和 UDP 协议的端口过滤
- **端口保护模式**: 非白名单客户端 IP 访问受保护端口时被拦截，其他流量默认放行
- **本地访问白名单**: 127.0.0.1 的本地访问不做任何拦截
- **动态配置热重载**: 支持配置文件热更新，无需重启服务
- **多平台支持**: 支持 x86/x64、ARM32/64 架构
- **静态编译**: 无需 libc 依赖，可部署在 Alpine 等最小化系统
- **拦截日志**: 通过 perf event 实时输出被拦截的客户端 IP 和端口信息（INFO 级别）
- **优雅退出**: Ctrl+C 信号处理，2 秒内快速关闭，超时强制清理
- **Linux 4.x 兼容**: 支持 Linux 4.x 及以上版本

## 快速开始

### 构建

```bash
# 构建当前平台
make build

# 构建所有平台
make build-all

# 查看帮助
make help
```

### 运行

```bash
# 基本运行（指定网卡和配置文件）
sudo ./bin/tc-firewall -i eth0 -c /etc/tc-firewall/config.json

# 启用控制台输出查看拦截日志
sudo ./bin/tc-firewall -i eth0 -c config.json --log.console

# 调试模式（查看详细日志）
sudo ./bin/tc-firewall -i eth0 -c config.json --log.console --log.level=debug

# 不指定配置文件 - 允许所有流量（仅用于测试）
sudo ./bin/tc-firewall -i eth0
```

**注意**: 配置文件修改后会自动热重载，无需重启服务。

### 命令行参数

| 参数 | 短参数 | 说明 | 默认值 |
|------|--------|------|--------|
| `--interface` | `-i` | 网络接口名称 | `eth0` (必填) |
| `--config-path` | `-c` | 配置文件路径 | 无 (允许所有流量) |
| `--config-type` | `-t` | 配置文件类型 (json/yaml/toml) | `json` |
| `--version` | `-v` | 显示版本信息 | `false` |
| `--log.path` | - | 日志文件路径 | `/var/log` |
| `--log.level` | - | 日志级别 (debug/info/warn/error) | `info` |
| `--log.console` | - | 启用控制台输出 | `false` |

### 配置文件

支持 JSON、YAML、TOML 等格式。

**JSON 格式:**
```json
{
  "ips": ["192.168.1.100", "10.0.0.5"],
  "ports": [3306, 6379, 80, 443]
}
```

**YAML 格式:**
```yaml
ips:
  - 192.168.1.100
  - 10.0.0.5
ports:
  - 3306
  - 6379
```

> **注意**:
> - 目前仅支持精确 IP 地址匹配，暂不支持 CIDR 网段格式（如 `10.0.0.0/8`）。如需配置多个 IP，请逐个列出。
> - 配置文件修改后会自动热重载，无需重启服务。

**配置说明:**
- `ips`: 允许访问受保护端口的白名单客户端 IP 列表
- `ports`: 需要保护的服务器端口列表

## 过滤逻辑

| 客户端 IP | 目标端口 | 结果 |
|-----------|----------|------|
| 不在 `ips` | 在 `ports` | **拦截** |
| 在 `ips` | 在 `ports` | 放行 |
| 在 `ips` | 不在 `ports` | 放行 |
| 不在 `ips` | 不在 `ports` | 放行 |
| 127.0.0.1 | 任意端口 | 放行 (本地访问白名单) |

**总结**: 只有当"非白名单客户端 IP 访问受保护端口"时才拦截，其他情况放行。

### 拦截日志

当非白名单 IP 访问受保护端口被拦截时，日志会输出：

```
2026-01-28 12:40:00  [tc-firewall] INFO   BLOCKED: client=192.168.1.50 attempted access to protected port 3306/TCP
```

日志字段说明:
- `client`: 被拦截的客户端源 IP
- `protected port`: 受保护的目标端口
- `protocol`: 协议 (TCP/UDP)

默认日志级别为 `info`，拦截日志直接可见。如需查看调试信息，可设置 `--log.level=debug`。

**日志输出位置**:
- 默认: `/var/log/tc-firewall/tc-firewall.log`
- 控制台输出: 添加 `--log.console` 参数

## 多平台构建

| 平台 | 二进制文件 | 说明 |
|------|------------|------|
| amd64 | `tc-firewall` | x86_64 (默认) |
| 386 | `tc-firewall-386` | x86 (32位) |
| arm | `tc-firewall-arm` | ARM (32位) |
| arm64 | `tc-firewall-arm64` | ARM64 (aarch64) |

```bash
# 构建所有平台
make build-all

# 构建特定平台
make build-arm64    # 树莓派4/5
make build-amd64    # x86_64 服务器
```

## 工作原理

```
配置文件 (JSON/YAML)
        │
        ▼
┌─────────────────┐
│  ConfigManager  │ ─── viper 监控文件变化 ───► 热重载
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  PopulateMaps() │ ─── 写入 eBPF Map (protected_ips, protected_ports)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  LoadPortProt   │ ─── bpf2go 编译的 eBPF 程序
│   ectionObjects │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ link.AttachTCX  │ ─── 挂载到网络接口 (TC ingress)
└────────┬────────┘
         │
         ▼
   [内核 eBPF 程序]
   TC Ingress Hook
         │
         ▼
   ┌─────────────────────────────────┐
   │ 过滤逻辑:                       │
   │ 1. 检查 src_ip 是否在白名单     │
   │ 2. 检查 dst_port 是否受保护     │
   │ 3. 127.0.0.1 直接放行           │
   │ 4. 非白名单访问受保护端口 → DROP │
   └─────────────────────────────────┘
         │
         ▼
   perf_event_output ──► 用户态日志
```

## 架构说明

### 核心组件

| 组件 | 文件 | 说明 |
|------|------|------|
| eBPF 程序 | `ebpf/port_protection/port_protection.c` | TC ingress 过滤逻辑 |
| eBPF 绑定 | `ebpf/port_protection/*.go` | bpf2go 自动生成 |
| 命令行入口 | `main.go` | 参数解析、初始化 |
| TC 防火墙 | `internal/cmd/tc.go` | eBPF 加载、Map 填充、事件读取 |
| 配置管理 | `pkg/viper.go` | 配置文件热重载 |
| 日志 | `pkg/logger/` | zap 日志库 |

### eBPF Map

| Map 名称 | 类型 | Key | Value | 用途 |
|----------|------|-----|-------|------|
| `protected_ips` | HASH | uint32 (IP) | uint8 (1) | 白名单 IP |
| `protected_ports` | HASH | uint16 (端口) | uint8 (1) | 受保护端口 |
| `events` | PERF_EVENT_ARRAY | - | drop_event | 拦截事件输出 |

### 性能特点

| 特性 | 说明 |
|------|------|
| **包处理延迟** | < 1μs（内核态直接处理，无用户态拷贝） |
| **并发连接** | 无状态过滤，不影响连接数 |
| **内存占用** | 仅 eBPF Map 开销（约几 MB） |
| **CPU 开销** | 仅命中过滤规则时进行 Map 查询 |

## 系统要求

- **Linux Kernel**: 4.x, 5.x, 6.x (推荐 5.10+)
- **CAP_NET_ADMIN**: 权限 (用于操作 TC)
- **eBPF**: 需要足够的内存限制 (或 root 权限)

### 验证内核支持

```bash
# 检查 TC 支持
tc filter show

# 检查 eBPF 支持
bpftool prog list

# 查看内核版本
uname -r
```

## 常见问题

### 1. 程序启动失败

```bash
# 检查权限
sudo ./bin/tc-firewall -i eth0 -c config.json

# 如果报错 "permission denied"，确保有 CAP_NET_ADMIN 权限
```

### 2. 所有流量都被拦截

检查配置文件格式是否正确：

```bash
# 验证 JSON 格式
cat config.json | python3 -m json.tool

# 查看 map 内容
sudo bpftool map dump name protected_ips
sudo bpftool map dump name protected_ports
```

### 3. 特定 IP 无法访问

确认客户端 IP 已在配置文件的 `ips` 列表中：

```json
{
  "ips": ["192.168.1.100"],
  "ports": [3306]
}
```

### 4. 本地访问被拦截

127.0.0.1 的访问默认是放行的，无需配置。如果本地访问被拦截，检查服务是否绑定在 127.0.0.1。

### 5. 查看 TC 过滤器状态

```bash
# 查看已挂载的 TC 过滤器
sudo tc filter show dev eth0 ingress

# 查看 eBPF 程序
sudo bpftool prog list

# 查看 map 内容
sudo bpftool map dump name protected_ips
sudo bpftool map dump name protected_ports
```

### 6. 没有拦截日志输出

如果确认有流量被拦截（如 tcpdump 显示 SYN 无响应），但没有 BLOCKED 日志：

```bash
# 1. 确认日志级别为 info（默认）
sudo ./bin/tc-firewall -i eth0 -c config.json --log.console

# 2. 检查 perf event 是否正确读取
sudo bpftool prog list | grep tc_ingress_filter
sudo bpftool net list

# 3. 验证 eBPF 程序正常挂载
sudo tc filter show dev eth0 ingress
```

### 7. 程序关闭缓慢

tc-firewall 已实现优雅退出机制：
- 收到 Ctrl+C 或 SIGTERM 信号后，2 秒内完成资源清理
- 如果超时，会强制关闭并输出警告日志
- 无需手动清理 TC 过滤器，程序退出时会自动卸载

## 卸载

```bash
# 停止 tc-firewall 程序 (Ctrl+C)
# 程序会自动清理 TC 过滤器和 eBPF 资源

# 如需手动清理 TC 过滤器（异常情况）
sudo tc filter del dev eth0 ingress
sudo tc filter del dev eth0 egress

# 清理 BPF pins (如果使用了 pin)
sudo rm -rf /sys/fs/bpf/tc/
```

## 相关链接

- [cilium/ebpf](https://github.com/cilium/ebpf) - eBPF Go 库
- [ebpf-go.dev](https://ebpf-go.dev) - eBPF Go 官方文档
- [Linux TC (Traffic Control)](https://docs.kernel.org/networking/tc.html) - Linux TC 文档
- [bpftool](https://docs.kernel.org/bpf/bpftool.html) - eBPF 调试工具

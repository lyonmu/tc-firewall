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
- **拦截日志**: 通过 perf event 输出被拦截的客户端 IP 信息
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
# 不指定配置文件 - 允许所有流量
sudo ./bin/tc-firewall -i <interface>

# 指定配置文件 - 应用访问限制
sudo ./bin/tc-firewall -i <interface> -c /etc/tc-firewall/config.json

# 启用动态配置热重载
sudo ./bin/tc-firewall -i <interface> -c /etc/tc-firewall/config.json

# 配置文件热重载是自动的，无需额外参数
```

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
  "ips": ["192.168.1.100", "10.0.0.0/8"],
  "ports": [3306, 6379, 80, 443]
}
```

**YAML 格式:**
```yaml
ips:
  - 192.168.1.100
  - 10.0.0.0/8
ports:
  - 3306
  - 6379
```

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
2026-01-26 21:40:00  [tc-firewall] DEBUG  BLOCKED: src_ip=192.168.1.50 port=3306 protocol=TCP dir=ingress
```

日志字段说明:
- `src_ip`: 被拦截的客户端源 IP
- `port`: 目标端口
- `protocol`: 协议 (TCP/UDP)
- `dir`: 方向 (ingress/egress)

## 动态配置热重载

tc-firewall 会自动监控配置文件的变化：

```bash
sudo ./bin/tc-firewall -i eth0 -c /etc/tc-firewall/config.json
```

当配置文件被修改时，防火墙会自动重新加载规则，无需重启服务。

## 日志配置

默认日志保存在 `/var/log/tc-firewall/tc-firewall.log`，可通过命令行参数配置：

```bash
# 启用控制台输出
sudo ./bin/tc-firewall -i eth0 -c config.json --log.console

# 设置日志级别为 debug
sudo ./bin/tc-firewall -i eth0 -c config.json --log.level=debug
```

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

## 卸载

```bash
# 停止 tc-firewall 程序 (Ctrl+C)

# 手动清理 TC 过滤器
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

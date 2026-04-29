# AGENTS.md - tc-firewall Project Guidelines

## Project Overview
TC-based eBPF firewall in Go 1.24.9. Uses TC ingress hook for packet filtering with config hot-reload.
**Deps**: cilium/ebpf, alecthomas/kong, go.uber.org/zap, spf13/viper

---

## Build Commands

### Build
```bash
make build              # Build for amd64 (default)
make build-amd64        # Build for x86_64
make build-386         # Build for x86 (32-bit)
make build-arm          # Build for ARM (32-bit)
make build-arm64        # Build for ARM64
make build-all          # Build for all platforms
make ebpf               # Generate eBPF bindings (run after .c changes)
make clean              # Clean artifacts
```

### Test
```bash
go test ./...                            # All tests
go test -v -run TestName ./pkg/logger    # Single test by name
go test -cover ./...                     # With coverage
go test -race ./...                      # Race detector
```

### Lint & Format
```bash
go fmt ./...      # Format files
go vet ./...      # Static analysis
go mod tidy       # Clean dependencies
```

### Workflow
```bash
go mod tidy && make ebpf && make build
```

---

## Code Style

### Naming
| Type | Convention | Example |
|------|------------|---------|
| Packages | lowercase | `logger`, `config` |
| Structs | PascalCase | `TCFirewall`, `Config` |
| Variables | camelCase | `closeCh`, `cfg` |
| Constants | SCREAMING_SNAKE_CASE | `ProjectName` |
| Generics | Single uppercase | `ConfigManager[T any]` |

### Imports (3 groups, blank line between)
```go
import (
    "fmt"
    "sync"

    "github.com/cilium/ebpf"
    "go.uber.org/zap"

    "github.com/lyonmu/tc-firewall/internal/config"
)
```

### Struct Tags
```go
type Config struct {
    Version   bool             `short:"v" long:"version" default:"false"`
    Log       logger.LogConfig `embed:"" prefix:"log."`
    Interface string           `short:"i" long:"interface" required:"true"`
}
```
- Use `kong` for CLI, `mapstructure` for viper, `embed:""` for embedded structs

### Error Handling
```go
if err := fw.Load(); err != nil {
    return fmt.Errorf("load eBPF: %w", err)
}
```
- Always wrap with `%w`, use `errors.Is`/`errors.As` for sentinel errors
- Log: `global.GetLogger().Sugar().Errorf("context: %v", err)`

### Logging
- Use `zap` via `logger.NewZapLogger()`
- Global accessor: `global.GetLogger().Sugar().Infof("message")`

### Concurrency
- Thread-safety: `sync.RWMutex` for shared state (`internal/global/global.go`)
- Context: first param, respect cancellation
- Shutdown: channel-based interrupt

---

## Project Structure
```
tc-firewall/
├── main.go
├── internal/
│   ├── cmd/tc.go     # TC firewall logic (TCFirewall struct)
│   ├── config/       # Config parsing
│   └── global/       # Global state (logger, config accessors)
├── pkg/
│   ├── logger/       # Zap logger with lumberjack rotation
│   └── viper.go      # ConfigManager[T] for hot-reload
└── ebpf/
    └── port_protection/
        ├── port_protection.c  # eBPF TC ingress program
        └── gen.go             # bpf2go bindings
```

---

## Key Patterns

### Initialization
```go
fw, err := NewTCFirewall(configPath, configType)
defer fw.Close()
if err := fw.Load(); err != nil { /* handle */ }
if err := fw.Attach(ifaceName); err != nil { /* handle */ }
```

### Config Hot-Reload
```go
mgr := pkg.NewConfigManager[config.FirewallConfig]()
<-mgr.Watch() // Listen for changes
cfg := mgr.GetConfig()
```

### Shutdown
```bash
stopCh := make(chan os.Signal, 5)
signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)
<-stopCh
```

---

## Debugging

### Runtime Commands
```bash
sudo tc filter show dev eth0 ingress     # View TC filters
sudo bpftool prog list                    # List eBPF programs
sudo bpftool map dump name protected_ips  # Dump allowed IPs
sudo bpftool map dump name protected_ports # Dump protected ports
```

### Filter Logic
| Client IP | Target Port | Result |
|-----------|-------------|--------|
| NOT in `ips` | IN `ports` | **DROP** |
| IN `ips` | IN `ports` | ALLOW |
| NOT in `ips` | NOT in `ports` | ALLOW |
| 127.0.0.1 | ANY | ALLOW (localhost bypass) |

### Troubleshooting
| Issue | Solution |
|-------|----------|
| TC attach fails | Use RawLink/tc fallback (older kernels) |
| Map lookup fails | IPv4 only, no CIDR support |
| Hot-reload not working | Check fsnotify permissions |
| eBPF binding errors | Run `make ebpf` after .c changes |

---

## Hard Constraints
- **NEVER** suppress type errors
- **NEVER** commit unless explicitly requested
- **ALWAYS** run `make ebpf` after modifying `.c` files
- IPs stored in **big-endian** (network byte order) in eBPF maps — use `binary.BigEndian` for all IP conversions
- Use `errors.Is`/`errors.As` for error sentinel comparisons

## Build Quirks
- Static build: `CGO_ENABLED=0` with tags `sonic avx netgo osusergo`
- eBPF bindings: `make ebpf` runs `go generate` from `ebpf/` subdirectory, requires `bpf2go` tool (declared in `go.mod` via `tool` directive)
- Generated files: `ebpf/port_protection/portprotection_*.go` and `*.o` — do not edit, regenerate with `make ebpf`
- Tests: most packages test without root; eBPF/TC tests require kernel support and root

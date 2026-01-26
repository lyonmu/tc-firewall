package cmd

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/lyonmu/tc-firewall/ebpf/port_protection"
	"github.com/lyonmu/tc-firewall/internal/config"
	"github.com/lyonmu/tc-firewall/internal/global"
	"github.com/lyonmu/tc-firewall/pkg"
)

// DropEvent represents a dropped packet event from eBPF
type DropEvent struct {
	SrcIP    uint32
	Port     uint16
	Protocol uint8
	Dir      uint8 // 0=ingress, 1=egress
}

// protocolName returns protocol name from number
func protocolName(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("%d", p)
	}
}

// directionName returns direction name
func directionName(d uint8) string {
	if d == 0 {
		return "ingress"
	}
	return "egress"
}

// intToIP converts uint32 to net.IP
func intToIP(i uint32) net.IP {
	return net.IPv4(byte(i), byte(i>>8), byte(i>>16), byte(i>>24))
}

// TCFirewall handles the TC-based port protection eBPF program with dynamic config hot-reload
type TCFirewall struct {
	objs      port_protection.PortProtectionObjects
	ingress   link.Link
	configMgr *pkg.ConfigManager[config.FirewallConfig]
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// NewTCFirewall creates a new TC firewall instance with optional dynamic config hot-reload
func NewTCFirewall(configPath string, configType string) (*TCFirewall, error) {
	fw := &TCFirewall{
		stopCh: make(chan struct{}),
	}

	if configPath != "" {
		// Use ConfigManager for dynamic hot-reload
		fw.configMgr = pkg.NewConfigManager[config.FirewallConfig]()
		if err := fw.configMgr.LoadConfig(configPath, configType); err != nil {
			return nil, fmt.Errorf("load config: %w", err)
		}
	}

	return fw, nil
}

// Load loads the eBPF programs and maps into the kernel
func (fw *TCFirewall) Load() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	if err := port_protection.LoadPortProtectionObjects(&fw.objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}

	return nil
}

// Attach attaches the TC program to the network interface (ingress only)
func (fw *TCFirewall) Attach(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("get interface %s: %w", ifaceName, err)
	}

	// Try TCX first (kernel 5.9+), fallback to RawLink for older kernels
	fw.ingress, err = link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   fw.objs.TcIngressFilter,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		// Fallback for Linux 4.x compatibility
		global.Logger.Sugar().Warnf("TCX attach failed (%v), trying raw link fallback", err)
		fw.ingress, err = link.AttachRawLink(link.RawLinkOptions{
			Target:   iface.Index,
			Program:  fw.objs.TcIngressFilter,
			Attach:   ebpf.AttachNone,
			Flags:    0,
		})
	}
	if err != nil {
		return fmt.Errorf("attach TC ingress: %w", err)
	}

	return nil
}

// PopulateMaps populates the eBPF maps with the current configuration
func (fw *TCFirewall) PopulateMaps() error {
	var cfg config.FirewallConfig

	if fw.configMgr != nil {
		cfg = fw.configMgr.GetConfig()
	}

	if cfg.AllowedIPs == nil && cfg.AllowedPorts == nil {
		global.Logger.Sugar().Debug("PopulateMaps: no config, allowing all traffic")
		return nil // Allow all if no config
	}

	global.Logger.Sugar().Debugf("PopulateMaps: got %d IPs and %d ports from config", len(cfg.AllowedIPs), len(cfg.AllowedPorts))

	// Build maps for efficient lookup
	allowedIPs := make(map[string]bool)
	for _, ipStr := range cfg.AllowedIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			global.Logger.Sugar().Warnf("PopulateMaps: invalid IP format '%s', skipping", ipStr)
			continue
		}
		ipBytes := ip.To4()
		if ipBytes == nil {
			global.Logger.Sugar().Warnf("PopulateMaps: IP '%s' is not IPv4, skipping", ipStr)
			continue
		}
		allowedIPs[ipStr] = true
	}

	allowedPorts := make(map[uint16]bool)
	for _, port := range cfg.AllowedPorts {
		allowedPorts[port] = true
	}

	// Populate IP map: IPs that are allowed to access protected ports
	one := uint8(1)
	ipCount := 0
	for ipStr := range allowedIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		ipBytes := ip.To4()
		if ipBytes == nil {
			continue
		}
		ipUint := binary.BigEndian.Uint32(ipBytes)
		global.Logger.Sugar().Debugf("PopulateMaps: adding IP %s -> uint32 %d (0x%08x)", ipStr, ipUint, ipUint)
		if err := fw.objs.ProtectedIps.Update(ipUint, one, ebpf.UpdateAny); err != nil {
			global.Logger.Sugar().Errorf("PopulateMaps: failed to update IP map for %s: %v", ipStr, err)
			return fmt.Errorf("update IP map for %s: %w", ipStr, err)
		}
		ipCount++
	}

	// Populate port map: ports that are protected
	portCount := 0
	for port := range allowedPorts {
		global.Logger.Sugar().Debugf("PopulateMaps: adding protected port %d", port)
		if err := fw.objs.ProtectedPorts.Update(port, one, ebpf.UpdateAny); err != nil {
			global.Logger.Sugar().Errorf("PopulateMaps: failed to update port map for %d: %v", port, err)
			return fmt.Errorf("update port map for %d: %w", port, err)
		}
		portCount++
	}

	global.Logger.Sugar().Infof("PopulateMaps: successfully populated %d IPs and %d ports to eBPF maps", ipCount, portCount)
	return nil
}

// ClearMaps clears all entries from the eBPF maps
func (fw *TCFirewall) ClearMaps() error {
	if fw.objs.ProtectedIps != nil {
		var ipKey uint32
		var ipValue uint8
		iter := fw.objs.ProtectedIps.Iterate()
		for iter.Next(&ipKey, &ipValue) {
			if err := fw.objs.ProtectedIps.Delete(ipKey); err != nil {
				return fmt.Errorf("delete IP from map: %w", err)
			}
		}
	}

	if fw.objs.ProtectedPorts != nil {
		var portKey uint16
		var portValue uint8
		iter := fw.objs.ProtectedPorts.Iterate()
		for iter.Next(&portKey, &portValue) {
			if err := fw.objs.ProtectedPorts.Delete(portKey); err != nil {
				return fmt.Errorf("delete port from map: %w", err)
			}
		}
	}

	return nil
}

// ReloadConfig reloads the configuration from the config manager
func (fw *TCFirewall) ReloadConfig() error {
	// Clear and repopulate maps with new config
	if err := fw.ClearMaps(); err != nil {
		return fmt.Errorf("clear maps: %w", err)
	}

	if err := fw.PopulateMaps(); err != nil {
		return fmt.Errorf("populate maps: %w", err)
	}

	return nil
}

// startConfigWatcher starts the background goroutine to watch for config changes
func (fw *TCFirewall) startConfigWatcher() {
	if fw.configMgr == nil {
		return
	}

	fw.wg.Add(1)
	go func() {
		defer fw.wg.Done()
		for {
			select {
			case <-fw.configMgr.Watch():
				global.Logger.Sugar().Info("Config file changed, reloading...")
				if err := fw.ReloadConfig(); err != nil {
					global.Logger.Sugar().Errorf("Failed to reload config: %v", err)
				} else {
					global.Logger.Sugar().Info("Config successfully reloaded and eBPF maps updated")
				}
			case <-fw.stopCh:
				return
			}
		}
	}()
}

// startEventReader starts reading drop events from the perf buffer
func (fw *TCFirewall) startEventReader() {
	if fw.objs.Events == nil {
		return
	}

	rd, err := perf.NewReader(fw.objs.Events, 4096)
	if err != nil {
		global.Logger.Sugar().Errorf("Failed to create perf reader: %v", err)
		return
	}

	fw.wg.Add(1)
	go func() {
		defer fw.wg.Done()
		defer rd.Close()

		for {
			select {
			case <-fw.stopCh:
				return
			default:
				record, err := rd.Read()
				if err != nil {
					if err == perf.ErrClosed {
						return
					}
					global.Logger.Sugar().Errorf("Failed to read from perf buffer: %v", err)
					time.Sleep(100 * time.Millisecond)
					continue
				}

				// Skip perf event header (8 bytes), read DropEvent from data
				if len(record.RawSample) < 8 {
					continue
				}

				data := record.RawSample[8:] // Skip perf header
				if len(data) < 10 { // DropEvent is 10 bytes
					continue
				}

				event := DropEvent{
					SrcIP:    uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24,
					Port:     uint16(data[4]) | uint16(data[5])<<8,
					Protocol: data[6],
					Dir:      data[7],
				}

				global.Logger.Sugar().Debugf("BLOCKED: src_ip=%s port=%d protocol=%s dir=%s",
					intToIP(event.SrcIP).String(),
					event.Port,
					protocolName(event.Protocol),
					directionName(event.Dir))
			}
		}
	}()
}

// Close closes all resources
func (fw *TCFirewall) Close() error {
	// Stop config watcher
	close(fw.stopCh)
	fw.wg.Wait()

	// Close config manager
	if fw.configMgr != nil {
		fw.configMgr.Close()
	}

	// Close eBPF resources
	if fw.ingress != nil {
		fw.ingress.Close()
	}
	if fw.objs.ProtectedIps != nil {
		fw.objs.ProtectedIps.Close()
	}
	if fw.objs.ProtectedPorts != nil {
		fw.objs.ProtectedPorts.Close()
	}
	fw.objs.Close()
	return nil
}

// StartTCFirewall starts the TC firewall with the given interface and config path
func StartTCFirewall(ifaceName string, configPath string, configType string) {
	// Create and configure firewall
	fw, err := NewTCFirewall(configPath, configType)
	if err != nil {
		global.Logger.Sugar().Fatalf("Create firewall: %v", err)
		os.Exit(1)
	}
	defer fw.Close()

	// Load eBPF programs
	if err := fw.Load(); err != nil {
		global.Logger.Sugar().Fatalf("Load eBPF: %v", err)
		os.Exit(1)
	}

	// Populate maps with config
	if err := fw.PopulateMaps(); err != nil {
		global.Logger.Sugar().Fatalf("Populate maps: %v", err)
		os.Exit(1)
	}

	// Attach to interface (ingress only)
	if err := fw.Attach(ifaceName); err != nil {
		global.Logger.Sugar().Fatalf("Attach TC: %v", err)
		os.Exit(1)
	}

	// Start event reader for logging blocked packets
	fw.startEventReader()

	// Start watching for config changes if dynamic reload is enabled
	fw.startConfigWatcher()
	if fw.configMgr != nil {
		cfg := fw.configMgr.GetConfig()
		if len(cfg.AllowedIPs) > 0 && len(cfg.AllowedPorts) > 0 {
			global.Logger.Sugar().Infof("TC Firewall active on %s - blocking non-allowed IPs from %d protected ports (ingress only)", ifaceName, len(cfg.AllowedPorts))
		} else {
			global.Logger.Sugar().Errorf("TC Firewall active on %s - no restrictions configured (allow all mode)", ifaceName)
			os.Exit(0)
		}
	} else {
		global.Logger.Sugar().Errorf("TC Firewall active on %s - no restrictions configured (allow all mode)", ifaceName)
		os.Exit(0)
	}

	// Wait for shutdown
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	global.Logger.Sugar().Info("Shutting down TC Firewall...")
}

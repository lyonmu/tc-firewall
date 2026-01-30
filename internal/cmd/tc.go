package cmd

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
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

// intToIP converts uint32 to net.IP (using little-endian byte order as stored by eBPF)
func intToIP(i uint32) net.IP {
	return net.IPv4(byte(i), byte(i>>8), byte(i>>16), byte(i>>24))
}

// TCFirewall handles the TC-based port protection eBPF program with dynamic config hot-reload
type TCFirewall struct {
	objs          port_protection.PortProtectionObjects
	ingress       link.Link
	tcLinkCleanup func() // cleanup function for tc command created links
	configMgr     *pkg.ConfigManager[config.FirewallConfig]
	stopCh        chan struct{}
	wg            sync.WaitGroup
	eventRd       *perf.Reader // for graceful shutdown
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

	// Configure map pinning path for persistent maps
	// Use process ID to avoid conflicts between multiple instances
	pinPath := fmt.Sprintf("/sys/fs/bpf/tc-firewall-p%d", os.Getpid())

	// Create pin path directory if it doesn't exist
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return fmt.Errorf("create pin path directory %s: %w", pinPath, err)
	}

	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}

	if err := port_protection.LoadPortProtectionObjects(&fw.objs, opts); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}

	global.GetLogger().Sugar().Debug("Load: eBPF programs loaded successfully")
	return nil
}

// Attach attaches the TC program to the network interface (ingress only)
func (fw *TCFirewall) Attach(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("get interface %s: %w", ifaceName, err)
	}

	global.GetLogger().Sugar().Infof("Attach: Found interface %s with index %d", ifaceName, iface.Index)

	// Try TCX first (kernel 5.9+), fallback to RawLink for older kernels
	fw.ingress, err = link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   fw.objs.TcIngressFilter,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		// Try RawLink with AttachNone (kernel 4.x compatible)
		fw.ingress, err = link.AttachRawLink(link.RawLinkOptions{
			Target:  iface.Index,
			Program: fw.objs.TcIngressFilter,
			Attach:  ebpf.AttachNone, // For kernel 4.x, use AttachNone instead of AttachTCXIngress
			Flags:   0,
		})
	}
	if err != nil {
		// Final fallback: use tc command (kernel 4.x compatible)
		global.GetLogger().Sugar().Warnf("RawLink attach failed (%v), trying tc command fallback", err)
		err = fw.attachViaTCCommand(ifaceName)
	}
	if err != nil {
		return fmt.Errorf("attach TC ingress: %w", err)
	}

	global.GetLogger().Sugar().Infof("Attach: Successfully attached TC filter to %s (ingress)", ifaceName)
	return nil
}

// attachViaTCCommand uses bpftool to attach eBPF program (kernel 4.x compatible)
func (fw *TCFirewall) attachViaTCCommand(ifaceName string) error {
	// For kernel 4.x, we use bpftool to pin the program and attach via tc command
	// because cilium/ebpf's RawLink may not work on all 4.x versions

	// Use the same pin path format as Load()
	pinBase := fmt.Sprintf("/sys/fs/bpf/tc-firewall-p%d", os.Getpid())
	progPath := pinBase + "/tc_ingress_filter"

	// Get program info to get the program name
	progInfo, err := fw.objs.TcIngressFilter.Info()
	if err != nil {
		return fmt.Errorf("get program info: %w", err)
	}
	progName := progInfo.Name

	global.GetLogger().Sugar().Debugf("attachViaTCCommand: pinning program '%s' to %s", progName, progPath)

	// Use bpftool to pin the eBPF program
	// Different bpftool versions have different argument orders, try both
	var pinCmd *exec.Cmd
	var output []byte

	// Try standard syntax: bpftool prog pin name <name> <path>
	pinCmd = exec.Command("bpftool", "prog", "pin", "name", progName, progPath)
	output, err = pinCmd.CombinedOutput()
	if err != nil {
		global.GetLogger().Sugar().Warnf("pin program with name-first syntax failed (%v), trying path-first syntax", err)
		// Try alternative syntax: bpftool prog pin <path> name <name>
		pinCmd = exec.Command("bpftool", "prog", "pin", progPath, "name", progName)
		output, err = pinCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("pin program (name=%s, path=%s): %w, output: %s", progName, progPath, err, string(output))
		}
	}

	// Create clsact qdisc (ignore "file exists" error)
	qdiscCmd := exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact")
	if err := qdiscCmd.Run(); err != nil {
		if !strings.Contains(err.Error(), "file exists") &&
			!strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("add clsact qdisc: %w", err)
		}
	}

	// Add eBPF filter using pinned object
	filterCmd := exec.Command("tc", "filter", "add", "dev", ifaceName, "ingress",
		"bpf", "direct-action", "object-pinned", progPath)
	if err := filterCmd.Run(); err != nil {
		return fmt.Errorf("add TC filter: %w", err)
	}

	// Store cleanup function for Close()
	fw.tcLinkCleanup = func() {
		exec.Command("tc", "filter", "del", "dev", ifaceName, "ingress").Run()
		os.Remove(progPath)
	}
	fw.ingress = nil // No link to close via cilium/ebpf

	global.GetLogger().Sugar().Infof("attachViaTCCommand: successfully attached TC filter via tc command to %s", ifaceName)
	return nil
}

// PopulateMaps populates the eBPF maps with the current configuration
func (fw *TCFirewall) PopulateMaps() error {
	var cfg config.FirewallConfig

	if fw.configMgr != nil {
		cfg = fw.configMgr.GetConfig()
	}

	if cfg.AllowedIPs == nil && cfg.AllowedPorts == nil {
		global.GetLogger().Sugar().Debug("PopulateMaps: no config, allowing all traffic")
		return nil // Allow all if no config
	}

	global.GetLogger().Sugar().Debugf("PopulateMaps: got %d IPs and %d ports from config", len(cfg.AllowedIPs), len(cfg.AllowedPorts))

	// Build maps for efficient lookup
	allowedIPs := make(map[string]bool)
	for _, ipStr := range cfg.AllowedIPs {
		// Check if it's a CIDR format
		if _, _, err := net.ParseCIDR(ipStr); err == nil {
			global.GetLogger().Sugar().Warnf("PopulateMaps: CIDR format '%s' is not supported. Only exact IP addresses are supported. Use individual IPs like '10.0.0.1' instead of '10.0.0.0/8'. Skipping.", ipStr)
			continue
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			global.GetLogger().Sugar().Warnf("PopulateMaps: invalid IP format '%s', skipping", ipStr)
			continue
		}
		ipBytes := ip.To4()
		if ipBytes == nil {
			global.GetLogger().Sugar().Warnf("PopulateMaps: IP '%s' is not IPv4, skipping", ipStr)
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
			global.GetLogger().Sugar().Warnf("PopulateMaps: invalid IP '%s', skipping", ipStr)
			continue
		}
		ipBytes := ip.To4()
		if ipBytes == nil {
			global.GetLogger().Sugar().Warnf("PopulateMaps: IP '%s' is not IPv4, skipping", ipStr)
			continue
		}
		// Use LittleEndian so the in-memory byte representation matches what eBPF expects
		// eBPF ip->saddr on x86 is stored in little-endian format
		ipUint := binary.LittleEndian.Uint32(ipBytes)
		global.GetLogger().Sugar().Debugf("PopulateMaps: adding IP %s -> uint32 %d (0x%08x)", ipStr, ipUint, ipUint)
		if err := fw.objs.ProtectedIps.Update(ipUint, one, ebpf.UpdateAny); err != nil {
			global.GetLogger().Sugar().Errorf("PopulateMaps: failed to update IP map for %s: %v", ipStr, err)
			return fmt.Errorf("update IP map for %s: %w", ipStr, err)
		}
		ipCount++
	}

	if ipCount > 0 {
		global.GetLogger().Sugar().Debugf("PopulateMaps: Total IPs in map: %d", ipCount)
	} else {
		global.GetLogger().Sugar().Warn("PopulateMaps: No IPs were added to the map!")
	}

	// Populate port map: ports that are protected
	portCount := 0
	for port := range allowedPorts {
		global.GetLogger().Sugar().Debugf("PopulateMaps: adding protected port %d", port)
		if err := fw.objs.ProtectedPorts.Update(port, one, ebpf.UpdateAny); err != nil {
			global.GetLogger().Sugar().Errorf("PopulateMaps: failed to update port map for %d: %v", port, err)
			return fmt.Errorf("update port map for %d: %w", port, err)
		}
		portCount++
	}

	if portCount > 0 {
		global.GetLogger().Sugar().Debugf("PopulateMaps: Total ports in map: %d", portCount)
	} else {
		global.GetLogger().Sugar().Warn("PopulateMaps: No ports were added to the map!")
	}

	global.GetLogger().Sugar().Debugf("PopulateMaps: successfully populated %d IPs and %d ports to eBPF maps", ipCount, portCount)
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
// This function performs atomic reload to avoid security gaps during reconfiguration
func (fw *TCFirewall) ReloadConfig() error {
	// Backup current config
	var oldCfg config.FirewallConfig
	if fw.configMgr != nil {
		oldCfg = fw.configMgr.GetConfig()
	}

	// Try to build new maps
	newIPs := make(map[uint32]uint8)
	newPorts := make(map[uint16]uint8)

	cfg := fw.configMgr.GetConfig()
	one := uint8(1)

	// Build IP map
	for _, ipStr := range cfg.AllowedIPs {
		if _, _, err := net.ParseCIDR(ipStr); err == nil {
			global.GetLogger().Sugar().Warnf("ReloadConfig: CIDR format '%s' is not supported, skipping", ipStr)
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			global.GetLogger().Sugar().Warnf("ReloadConfig: invalid IP format '%s', skipping", ipStr)
			continue
		}
		ipBytes := ip.To4()
		if ipBytes == nil {
			global.GetLogger().Sugar().Warnf("ReloadConfig: IP '%s' is not IPv4, skipping", ipStr)
			continue
		}
		ipUint := binary.LittleEndian.Uint32(ipBytes)
		newIPs[ipUint] = one
	}

	// Build port map
	for _, port := range cfg.AllowedPorts {
		newPorts[port] = one
	}

	// Clear old maps and populate new ones atomically
	// If we fail during population, we try to restore old entries
	if err := fw.ClearMaps(); err != nil {
		// Restore old config if clear fails
		fw.restoreMaps(oldCfg)
		return fmt.Errorf("clear maps: %w", err)
	}

	// Populate new IPs
	for ipUint := range newIPs {
		if err := fw.objs.ProtectedIps.Update(ipUint, one, ebpf.UpdateAny); err != nil {
			// Restore old config if update fails
			fw.restoreMaps(oldCfg)
			return fmt.Errorf("update IP map: %w", err)
		}
	}

	// Populate new ports
	for port := range newPorts {
		if err := fw.objs.ProtectedPorts.Update(port, one, ebpf.UpdateAny); err != nil {
			// Restore old config if update fails
			fw.restoreMaps(oldCfg)
			return fmt.Errorf("update port map: %w", err)
		}
	}

	global.GetLogger().Sugar().Info("Config successfully reloaded atomically")
	return nil
}

// restoreMaps restores the maps to the given config
func (fw *TCFirewall) restoreMaps(cfg config.FirewallConfig) {
	one := uint8(1)

	// Clear current maps
	fw.ClearMaps()

	// Restore IPs
	for _, ipStr := range cfg.AllowedIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		ipBytes := ip.To4()
		if ipBytes == nil {
			continue
		}
		ipUint := binary.LittleEndian.Uint32(ipBytes)
		fw.objs.ProtectedIps.Update(ipUint, one, ebpf.UpdateAny)
	}

	// Restore ports
	for _, port := range cfg.AllowedPorts {
		fw.objs.ProtectedPorts.Update(port, one, ebpf.UpdateAny)
	}
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
				global.GetLogger().Sugar().Info("Config file changed, reloading...")
				if err := fw.ReloadConfig(); err != nil {
					global.GetLogger().Sugar().Errorf("Failed to reload config: %v", err)
				} else {
					global.GetLogger().Sugar().Info("Config successfully reloaded and eBPF maps updated")
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

	// Use larger buffer for high-traffic scenarios (per CPU)
	rd, err := perf.NewReader(fw.objs.Events, 8192)
	if err != nil {
		global.GetLogger().Sugar().Errorf("Failed to create perf reader: %v", err)
		return
	}
	fw.eventRd = rd
	global.GetLogger().Sugar().Debug("Event reader started successfully")

	fw.wg.Add(1)
	go func() {
		defer fw.wg.Done()
		defer func() {
			fw.eventRd = nil
		}()

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
					// Ignore errors during shutdown (reader closed)
					if strings.Contains(err.Error(), "closed") || strings.Contains(err.Error(), "epoll") {
						return
					}
					global.GetLogger().Sugar().Errorf("Failed to read from perf buffer: %v", err)
					time.Sleep(100 * time.Millisecond)
					continue
				}

				// RawSample contains the event data directly (no perf header to skip)
				data := record.RawSample
				if len(data) < 8 { // DropEvent is 8 bytes (4+2+1+1)
					continue
				}

				// Parse event data (little-endian as stored by eBPF)
				event := DropEvent{
					SrcIP:    binary.LittleEndian.Uint32(data[0:4]),
					Port:     binary.LittleEndian.Uint16(data[4:6]),
					Protocol: data[6],
				}

				global.GetLogger().Sugar().Debugf("BLOCKED: client=%s attempted access to protected port %d/%s",
					intToIP(event.SrcIP).String(),
					event.Port,
					protocolName(event.Protocol))
			}
		}
	}()
}

// Close closes all resources
func (fw *TCFirewall) Close() error {
	global.GetLogger().Sugar().Info("Shutting down TC Firewall...")

	// Remove pinned maps after closing (cleanup)
	// Use the same pin path format as Load()
	defer func() {
		pinPath := fmt.Sprintf("/sys/fs/bpf/tc-firewall-p%d", os.Getpid())
		if err := os.RemoveAll(pinPath); err != nil {
			global.GetLogger().Sugar().Warnf("Failed to remove pin path %s: %v", pinPath, err)
		} else {
			global.GetLogger().Sugar().Debugf("Cleaned up pin path: %s", pinPath)
		}
	}()

	// Signal all goroutines to stop
	close(fw.stopCh)

	// Close event reader first to unblock Read()
	if fw.eventRd != nil {
		fw.eventRd.Close()
	}

	// Wait for goroutines to exit with timeout
	done := make(chan struct{})
	go func() {
		fw.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Goroutines exited cleanly
	case <-time.After(2 * time.Second):
		global.GetLogger().Sugar().Warn("Timeout waiting for goroutines to exit, forcing shutdown")
	}

	// Close config manager
	if fw.configMgr != nil {
		fw.configMgr.Close()
	}

	// Close eBPF resources
	// Cleanup tc command created link first (if any)
	if fw.tcLinkCleanup != nil {
		fw.tcLinkCleanup()
		fw.tcLinkCleanup = nil
	}
	if fw.ingress != nil {
		fw.ingress.Close()
	}
	if fw.objs.ProtectedIps != nil {
		fw.objs.ProtectedIps.Close()
	}
	if fw.objs.ProtectedPorts != nil {
		fw.objs.ProtectedPorts.Close()
	}
	if fw.objs.LastEventTs != nil {
		fw.objs.LastEventTs.Close()
	}
	fw.objs.Close()
	return nil
}

// DumpMaps dumps the contents of eBPF maps for debugging
func (fw *TCFirewall) DumpMaps() {
	global.GetLogger().Sugar().Debug("=== Dumping eBPF Map Contents ===")

	// Dump IP map
	if fw.objs.ProtectedIps != nil {
		var ipKey uint32
		var ipValue uint8
		iter := fw.objs.ProtectedIps.Iterate()
		count := 0
		for iter.Next(&ipKey, &ipValue) {
			ip := intToIP(ipKey)
			global.GetLogger().Sugar().Debugf("  IP map entry: %s -> %d", ip.String(), ipValue)
			count++
		}
		global.GetLogger().Sugar().Debugf("  Total IP entries: %d", count)
	}

	// Dump port map
	if fw.objs.ProtectedPorts != nil {
		var portKey uint16
		var portValue uint8
		iter := fw.objs.ProtectedPorts.Iterate()
		count := 0
		for iter.Next(&portKey, &portValue) {
			global.GetLogger().Sugar().Debugf("  Port map entry: %d -> %d", portKey, portValue)
			count++
		}
		global.GetLogger().Sugar().Debugf("  Total port entries: %d", count)
	}

	global.GetLogger().Sugar().Debug("=== End Map Dump ===")
}

// RunTCFirewall runs the TC firewall with pre-loaded and attached firewall instance
// This function handles the blocking event loop and shutdown
func RunTCFirewall(fw *TCFirewall, ifaceName string) {
	// Start event reader for logging blocked packets
	fw.startEventReader()

	// Start watching for config changes if dynamic reload is enabled
	fw.startConfigWatcher()
	if fw.configMgr != nil {
		cfg := fw.configMgr.GetConfig()
		if len(cfg.AllowedIPs) == 0 && len(cfg.AllowedPorts) == 0 {
			global.GetLogger().Sugar().Infof("TC Firewall active on %s - no restrictions configured (allow all mode)", ifaceName)
			return
		}

		if len(cfg.AllowedPorts) > 0 {
			global.GetLogger().Sugar().Infof("TC Firewall active on %s - blocking non-allowed IPs from %d protected ports (ingress only)", ifaceName, len(cfg.AllowedPorts))
		} else {
			global.GetLogger().Sugar().Infof("TC Firewall active on %s - IP whitelist configured, no ports protected (allow all mode)", ifaceName)
		}
		if len(cfg.AllowedIPs) > 0 {
			global.GetLogger().Sugar().Debugf("  - Whitelisted IPs: %d", len(cfg.AllowedIPs))
		}
		// Dump maps for verification
		fw.DumpMaps()
	} else {
		global.GetLogger().Sugar().Infof("TC Firewall active on %s - no restrictions configured (allow all mode)", ifaceName)
	}

	// Wait for shutdown
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}

// StartTCFirewall starts the TC firewall with the given interface and config path
// Deprecated: Use NewTCFirewall followed by Load, Attach, and RunTCFirewall for proper error handling
func StartTCFirewall(ifaceName string, configPath string, configType string) {
	// Create and configure firewall
	fw, err := NewTCFirewall(configPath, configType)
	if err != nil {
		global.GetLogger().Sugar().Fatalf("Create firewall: %v", err)
		os.Exit(1)
	}
	defer fw.Close()

	// Load eBPF programs
	if err := fw.Load(); err != nil {
		global.GetLogger().Sugar().Fatalf("Load eBPF: %v", err)
		os.Exit(1)
	}

	// Populate maps with config
	if err := fw.PopulateMaps(); err != nil {
		global.GetLogger().Sugar().Fatalf("Populate maps: %v", err)
		os.Exit(1)
	}

	// Attach to interface (ingress only)
	if err := fw.Attach(ifaceName); err != nil {
		global.GetLogger().Sugar().Fatalf("Attach TC: %v", err)
		os.Exit(1)
	}

	// Run the firewall (blocking)
	RunTCFirewall(fw, ifaceName)
}

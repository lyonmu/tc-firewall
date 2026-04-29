package config

import (
	"fmt"
	"net"
	"slices"

	"github.com/alecthomas/kong"
	"github.com/lyonmu/tc-firewall/pkg/logger"
)

const (
	// MaxAllowedIPs is the maximum number of IPs allowed in the whitelist
	MaxAllowedIPs = 1024
	// MaxAllowedPorts is the maximum number of protected ports
	MaxAllowedPorts = 1024
)

type Config struct {
	Version    bool             `short:"v" long:"version" help:"显示版本信息" default:"false"`
	Log        logger.LogConfig `embed:"" prefix:"log."`
	Interface  string           `short:"i" long:"interface" default:"eth0" help:"Network interface to attach to" required:"true"`
	ConfigPath string           `short:"c" long:"config-path" default:"config.json" help:"Path to configuration file (optional, if file doesn't exist or is empty, allows all traffic)"`
	ConfigType string           `enum:"json,yaml,toml" default:"json" short:"t" long:"config-type" help:"Type of configuration (json, yaml, etc.) (optional, default is json)"`
}

// FirewallConfig holds the allowed IPs and ports
type FirewallConfig struct {
	AllowedIPs   []string `json:"ips,omitempty" mapstructure:"ips"`
	AllowedPorts []uint16 `json:"ports,omitempty" mapstructure:"ports"`
}

// Validate validates the firewall configuration and returns an error if invalid
func (fc *FirewallConfig) Validate() error {
	// Check IP count limit
	if len(fc.AllowedIPs) > MaxAllowedIPs {
		return fmt.Errorf("too many IPs: %d (max %d)", len(fc.AllowedIPs), MaxAllowedIPs)
	}

	// Validate each IP and check for duplicates
	seen := make(map[string]bool)
	for _, ipStr := range fc.AllowedIPs {
		// Check for CIDR (not supported)
		if _, _, err := net.ParseCIDR(ipStr); err == nil {
			return fmt.Errorf("CIDR notation not supported: %s (use individual IPs like '10.0.0.1')", ipStr)
		}

		// Validate IP format
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", ipStr)
		}

		// Check for IPv6
		if ip.To4() == nil {
			return fmt.Errorf("IPv6 not supported: %s (only IPv4 allowed)", ipStr)
		}

		// Check for duplicates
		if seen[ipStr] {
			return fmt.Errorf("duplicate IP: %s", ipStr)
		}
		seen[ipStr] = true
	}

	// Check port count limit
	if len(fc.AllowedPorts) > MaxAllowedPorts {
		return fmt.Errorf("too many ports: %d (max %d)", len(fc.AllowedPorts), MaxAllowedPorts)
	}

	// Validate ports and check for duplicates
	slices.Sort(fc.AllowedPorts)
	for i, port := range fc.AllowedPorts {
		if port == 0 {
			return fmt.Errorf("invalid port: 0 (ports must be 1-65535)")
		}
		if i > 0 && fc.AllowedPorts[i-1] == port {
			return fmt.Errorf("duplicate port: %d", port)
		}
	}

	return nil
}

func Parse(cfg *Config) error {
	ctx := kong.Parse(cfg,
		kong.Name("tc-firewall"),
		kong.Description("TC-based eBPF firewall"),
		kong.UsageOnError(),
		kong.HelpOptions{Compact: true, Summary: true},
	)
	if ctx.Error != nil {
		return ctx.Error
	}
	return nil
}

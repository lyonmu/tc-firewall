package config

import (
	"github.com/alecthomas/kong"
	"github.com/lyonmu/tc-firewall/pkg/logger"
)

type Config struct {
	Version    bool             `short:"v" long:"version" help:"显示版本信息" default:"false"`
	Log        logger.LogConfig `embed:"" prefix:"log."`
	Interface  string           `short:"i" long:"interface" default:"eth0" help:"Network interface to attach to" required:"true"`
	ConfigPath string           `short:"c" long:"config-path" default:"config.json" help:"Path to configuration file (optional, default allows all traffic)" required:"true"`
	ConfigType string           `enum:"json,yaml,toml" default:"json" short:"t" long:"config-type" help:"Type of configuration (json, yaml, etc.) (optional, default is json)"`
}

// FirewallConfig holds the allowed IPs and ports
type FirewallConfig struct {
	AllowedIPs   []string `json:"ips,omitempty" mapstructure:"ips"`
	AllowedPorts []uint16 `json:"ports,omitempty" mapstructure:"ports"`
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

package main

import (
	"fmt"
	"os"

	"github.com/prometheus/common/version"

	"github.com/lyonmu/tc-firewall/internal/cmd"
	"github.com/lyonmu/tc-firewall/internal/config"
	"github.com/lyonmu/tc-firewall/internal/global"
	"github.com/lyonmu/tc-firewall/pkg/logger"
)

func main() {
	// Parse config
	var cfg config.Config
	if err := config.Parse(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Show version
	if cfg.Version {
		fmt.Println(version.Print("tc-firewall"))
		os.Exit(0)
	}

	// Initialize logger
	global.Cfg = &cfg
	global.Logger = logger.NewZapLogger(cfg.Log)
	global.Logger.Sugar().Info("TC Firewall starting...")

	cmd.StartTCFirewall(cfg.Interface, cfg.ConfigPath, cfg.ConfigType)
}

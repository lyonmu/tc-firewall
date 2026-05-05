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
	global.SetCfg(&cfg)
	log, err := logger.NewZapLogger(cfg.Log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	global.SetLogger(log)
	global.GetLogger().Sugar().Info("TC Firewall starting...")

	// Create firewall instance
	fw, err := cmd.NewTCFirewall(cfg.ConfigPath, cfg.ConfigType)
	if err != nil {
		global.GetLogger().Sugar().Fatalf("Create firewall: %v", err)
	}
	defer fw.Close()

	// Load eBPF programs
	if err := fw.Load(); err != nil {
		global.GetLogger().Sugar().Fatalf("Load eBPF: %v", err)
	}

	// Populate maps with config
	if err := fw.PopulateMaps(); err != nil {
		global.GetLogger().Sugar().Fatalf("Populate maps: %v", err)
	}

	// Attach to interface (ingress only)
	if err := fw.Attach(cfg.Interface); err != nil {
		global.GetLogger().Sugar().Fatalf("Attach TC: %v", err)
	}

	// Run the firewall (blocking)
	cmd.RunTCFirewall(fw, cfg.Interface)
}

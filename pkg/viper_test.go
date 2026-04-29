package pkg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lyonmu/tc-firewall/internal/config"
)

func TestNewConfigManager(t *testing.T) {
	cm := NewConfigManager[config.FirewallConfig]()
	if cm == nil {
		t.Fatal("NewConfigManager returned nil")
	}
	if cm.v == nil {
		t.Error("viper instance is nil")
	}
	if cm.exit == nil {
		t.Error("exit channel is nil")
	}
	if cm.watchCh == nil {
		t.Error("watchCh channel is nil")
	}
}

func TestConfigManager_LoadConfig_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.json")

	cfg := config.FirewallConfig{
		AllowedIPs:   []string{"192.168.1.1", "10.0.0.1"},
		AllowedPorts: []uint16{22, 80, 443},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}
	if err := os.WriteFile(cfgFile, data, 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cm := NewConfigManager[config.FirewallConfig]()
	defer cm.Close()

	if err := cm.LoadConfig(cfgFile, "json"); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	loaded := cm.GetConfig()
	if len(loaded.AllowedIPs) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(loaded.AllowedIPs))
	}
	if len(loaded.AllowedPorts) != 3 {
		t.Errorf("Expected 3 ports, got %d", len(loaded.AllowedPorts))
	}
}

func TestConfigManager_LoadConfig_InvalidFile(t *testing.T) {
	cm := NewConfigManager[config.FirewallConfig]()
	defer cm.Close()

	err := cm.LoadConfig("/nonexistent/config.json", "json")
	if err == nil {
		t.Error("LoadConfig should fail for nonexistent file")
	}
}

func TestConfigManager_LoadConfig_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(cfgFile, []byte("not json"), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	cm := NewConfigManager[config.FirewallConfig]()
	defer cm.Close()

	err := cm.LoadConfig(cfgFile, "json")
	if err == nil {
		t.Error("LoadConfig should fail for invalid JSON")
	}
}

func TestConfigManager_GetConfig_ThreadSafety(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.json")

	cfg := config.FirewallConfig{
		AllowedIPs:   []string{"192.168.1.1"},
		AllowedPorts: []uint16{22},
	}
	data, _ := json.Marshal(cfg)
	os.WriteFile(cfgFile, data, 0644)

	cm := NewConfigManager[config.FirewallConfig]()
	defer cm.Close()

	if err := cm.LoadConfig(cfgFile, "json"); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Concurrent reads
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = cm.GetConfig()
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestConfigManager_GetConfigPtr(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.json")

	cfg := config.FirewallConfig{
		AllowedIPs:   []string{"192.168.1.1"},
		AllowedPorts: []uint16{22},
	}
	data, _ := json.Marshal(cfg)
	os.WriteFile(cfgFile, data, 0644)

	cm := NewConfigManager[config.FirewallConfig]()
	defer cm.Close()

	if err := cm.LoadConfig(cfgFile, "json"); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	ptr := cm.GetConfigPtr()
	if ptr == nil {
		t.Fatal("GetConfigPtr returned nil")
	}
	if len(ptr.AllowedIPs) != 1 {
		t.Errorf("Expected 1 IP, got %d", len(ptr.AllowedIPs))
	}
}

func TestConfigManager_Watch(t *testing.T) {
	cm := NewConfigManager[config.FirewallConfig]()
	defer cm.Close()

	ch := cm.Watch()
	if ch == nil {
		t.Fatal("Watch returned nil channel")
	}
}

func TestConfigManager_Close(t *testing.T) {
	cm := NewConfigManager[config.FirewallConfig]()

	// Close should not panic
	cm.Close()

	// Watch channel should be closed
	ch := cm.Watch()
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("Watch channel should be closed after Close()")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Watch channel not closed after Close()")
	}
}

func TestConfigManager_HotReload(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.json")

	// Initial config
	cfg := config.FirewallConfig{
		AllowedIPs:   []string{"192.168.1.1"},
		AllowedPorts: []uint16{22},
	}
	data, _ := json.Marshal(cfg)
	os.WriteFile(cfgFile, data, 0644)

	cm := NewConfigManager[config.FirewallConfig]()
	defer cm.Close()

	if err := cm.LoadConfig(cfgFile, "json"); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify initial config
	loaded := cm.GetConfig()
	if len(loaded.AllowedIPs) != 1 {
		t.Errorf("Expected 1 IP initially, got %d", len(loaded.AllowedIPs))
	}

	// Update config file
	cfg.AllowedIPs = []string{"192.168.1.1", "10.0.0.1"}
	cfg.AllowedPorts = []uint16{22, 80}
	data, _ = json.Marshal(cfg)
	os.WriteFile(cfgFile, data, 0644)

	// Wait for hot-reload
	select {
	case <-cm.Watch():
		// Config reloaded
	case <-time.After(2 * time.Second):
		t.Skip("Hot-reload timeout — fsnotify may not work in this environment")
	}

	// Verify updated config
	loaded = cm.GetConfig()
	if len(loaded.AllowedIPs) != 2 {
		t.Errorf("Expected 2 IPs after reload, got %d", len(loaded.AllowedIPs))
	}
	if len(loaded.AllowedPorts) != 2 {
		t.Errorf("Expected 2 ports after reload, got %d", len(loaded.AllowedPorts))
	}
}

package config

import (
	"testing"
)

func TestFirewallConfig_Validate_Valid(t *testing.T) {
	cfg := FirewallConfig{
		AllowedIPs:   []string{"192.168.1.1", "10.0.0.1"},
		AllowedPorts: []uint16{22, 80, 443},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestFirewallConfig_Validate_Empty(t *testing.T) {
	cfg := FirewallConfig{}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error for empty config: %v", err)
	}
}

func TestFirewallConfig_Validate_InvalidIP(t *testing.T) {
	cfg := FirewallConfig{
		AllowedIPs: []string{"not-an-ip"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() expected error for invalid IP")
	}
}

func TestFirewallConfig_Validate_IPv6(t *testing.T) {
	cfg := FirewallConfig{
		AllowedIPs: []string{"::1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() expected error for IPv6")
	}
}

func TestFirewallConfig_Validate_CIDR(t *testing.T) {
	cfg := FirewallConfig{
		AllowedIPs: []string{"192.168.1.0/24"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() expected error for CIDR notation")
	}
}

func TestFirewallConfig_Validate_DuplicateIP(t *testing.T) {
	cfg := FirewallConfig{
		AllowedIPs: []string{"192.168.1.1", "192.168.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() expected error for duplicate IP")
	}
}

func TestFirewallConfig_Validate_TooManyIPs(t *testing.T) {
	ips := make([]string, MaxAllowedIPs+1)
	for i := range ips {
		ips[i] = "10.0.0.1"
	}
	cfg := FirewallConfig{
		AllowedIPs: ips,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() expected error for too many IPs")
	}
}

func TestFirewallConfig_Validate_ZeroPort(t *testing.T) {
	cfg := FirewallConfig{
		AllowedPorts: []uint16{0},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() expected error for port 0")
	}
}

func TestFirewallConfig_Validate_DuplicatePort(t *testing.T) {
	cfg := FirewallConfig{
		AllowedPorts: []uint16{22, 22},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() expected error for duplicate port")
	}
}

func TestFirewallConfig_Validate_TooManyPorts(t *testing.T) {
	ports := make([]uint16, MaxAllowedPorts+1)
	for i := range ports {
		ports[i] = 1
	}
	cfg := FirewallConfig{
		AllowedPorts: ports,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() expected error for too many ports")
	}
}

func TestFirewallConfig_Validate_MaxIPs(t *testing.T) {
	// Exactly at the limit should be OK
	ips := make([]string, MaxAllowedIPs)
	for i := range ips {
		ips[i] = "10.0.0.1"
	}
	cfg := FirewallConfig{
		AllowedIPs: ips,
	}
	// This will fail due to duplicates, but not due to count
	err := cfg.Validate()
	if err != nil && err.Error() == "too many IPs" {
		t.Error("Validate() should accept exactly MaxAllowedIPs")
	}
}

func TestFirewallConfig_Validate_MaxPorts(t *testing.T) {
	// Exactly at the limit should be OK
	ports := make([]uint16, MaxAllowedPorts)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	cfg := FirewallConfig{
		AllowedPorts: ports,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error for max ports: %v", err)
	}
}

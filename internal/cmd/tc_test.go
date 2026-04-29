package cmd

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestIntToIP_NetworkByteOrder(t *testing.T) {
	// 192.168.1.1 in network byte order (big-endian) = 0xC0A80101
	// This is what eBPF stores as ip->saddr
	networkOrderIP := uint32(0xC0A80101)

	result := intToIP(networkOrderIP)

	expected := net.IPv4(192, 168, 1, 1)
	if !result.Equal(expected) {
		t.Errorf("intToIP(0x%08X) = %s, want %s", networkOrderIP, result, expected)
	}
}

func TestIntToIP_Loopback(t *testing.T) {
	// 127.0.0.1 in network byte order = 0x7F000001
	networkOrderIP := uint32(0x7F000001)

	result := intToIP(networkOrderIP)

	expected := net.IPv4(127, 0, 0, 1)
	if !result.Equal(expected) {
		t.Errorf("intToIP(0x%08X) = %s, want %s", networkOrderIP, result, expected)
	}
}

func TestIPToUint32_NetworkByteOrder(t *testing.T) {
	// Verify that IP bytes are converted to big-endian uint32
	ip := net.ParseIP("192.168.1.1").To4()
	ipUint := binary.BigEndian.Uint32(ip)

	// 192.168.1.1 in big-endian = 0xC0A80101
	if ipUint != 0xC0A80101 {
		t.Errorf("BigEndian.Uint32(192.168.1.1) = 0x%08X, want 0xC0A80101", ipUint)
	}
}

func TestIPToUint32_LittleEndian_Wrong(t *testing.T) {
	// Demonstrate that LittleEndian produces wrong result for eBPF map keys
	ip := net.ParseIP("192.168.1.1").To4()
	littleEndian := binary.LittleEndian.Uint32(ip)
	bigEndian := binary.BigEndian.Uint32(ip)

	if littleEndian == bigEndian {
		t.Skip("LittleEndian and BigEndian produce same result (unlikely on x86)")
	}

	// On x86, LittleEndian gives 0x0101A8C0, BigEndian gives 0xC0A80101
	// eBPF uses network byte order (big-endian), so LittleEndian is WRONG
	t.Logf("LittleEndian: 0x%08X (WRONG for eBPF)", littleEndian)
	t.Logf("BigEndian:    0x%08X (CORRECT for eBPF)", bigEndian)
}

func TestIntToIP_AllOctets(t *testing.T) {
	tests := []struct {
		name     string
		input    uint32
		expected string
	}{
		{"zero", 0x00000000, "0.0.0.0"},
		{"loopback", 0x7F000001, "127.0.0.1"},
		{"class_a", 0x0A000001, "10.0.0.1"},
		{"class_b", 0xC0A80101, "192.168.1.1"},
		{"class_c", 0xAC100001, "172.16.0.1"},
		{"broadcast", 0xFFFFFFFF, "255.255.255.255"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := intToIP(tt.input)
			if result.String() != tt.expected {
				t.Errorf("intToIP(0x%08X) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIPToUint32_RoundTrip(t *testing.T) {
	// Verify that converting IP -> uint32 -> IP preserves the value
	ips := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"127.0.0.1",
		"0.0.0.0",
		"255.255.255.255",
	}

	for _, ipStr := range ips {
		t.Run(ipStr, func(t *testing.T) {
			ip := net.ParseIP(ipStr).To4()
			ipUint := binary.BigEndian.Uint32(ip)
			result := intToIP(ipUint)

			if !result.Equal(net.ParseIP(ipStr)) {
				t.Errorf("Round trip failed: %s -> %d -> %s", ipStr, ipUint, result)
			}
		})
	}
}

func TestValidateInterfaceName(t *testing.T) {
	tests := []struct {
		name    string
		iface   string
		wantErr bool
	}{
		{"valid_eth0", "eth0", false},
		{"valid_ens33", "ens33", false},
		{"valid_with_dash", "eth0-1", false},
		{"valid_with_dot", "eth0.100", false},
		{"valid_with_underscore", "eth_0", false},
		{"empty", "", true},
		{"too_long", "a123456789012345", true},
		{"invalid_space", "eth 0", true},
		{"invalid_special", "eth@0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInterfaceName(tt.iface)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateInterfaceName(%q) error = %v, wantErr %v", tt.iface, err, tt.wantErr)
			}
		})
	}
}

func TestProtocolName(t *testing.T) {
	tests := []struct {
		proto    uint8
		expected string
	}{
		{6, "TCP"},
		{17, "UDP"},
		{1, "1"},
		{0, "0"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := protocolName(tt.proto)
			if result != tt.expected {
				t.Errorf("protocolName(%d) = %s, want %s", tt.proto, result, tt.expected)
			}
		})
	}
}

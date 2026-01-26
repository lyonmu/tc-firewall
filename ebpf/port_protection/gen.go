package port_protection

//go:generate go tool bpf2go -tags linux --go-package port_protection PortProtection port_protection.c -- -I/usr/include/x86_64-linux-gnu

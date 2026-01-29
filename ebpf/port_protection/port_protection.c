//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

// Protocol constants
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif
#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

// Event structure for dropped packets (used with perf event output)
// Packed to ensure no compiler padding and consistent layout with userspace
struct __attribute__((packed)) drop_event {
    __u32 src_ip;      // Network byte order (big-endian)
    __u16 port;        // Network byte order (big-endian)
    __u8 protocol;     // IPPROTO_TCP or IPPROTO_UDP
    __u8 dir;          // 0=ingress, 1=egress
};

// Perf event array for sending drop events to userspace (compatible with Linux 4.x+)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 4);
} events SEC(".maps");

// Hash map for IPs that are allowed to access protected ports
// (value is just a presence flag, 1 = allowed)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // Enable map pinning for persistence
} protected_ips SEC(".maps");

// Hash map for protected ports
// (value is just a presence flag, 1 = protected)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // Enable map pinning for persistence
} protected_ports SEC(".maps");

// Rate limiting map - stores last event timestamp per CPU
// Prevents perf event DoS under high traffic attacks
// Using PERCPU_ARRAY to avoid contention between CPUs
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);  // last event timestamp in nanoseconds
} last_event_ts SEC(".maps");

// Rate limit: minimum interval between events (10ms = 100 events/sec)
#define EVENT_INTERVAL_NS 10000000ULL

#define LOCALHOST_IP 0x0100007F  //

// Helper: check if we can send a perf event (rate limiting)
// Returns 1 if event can be sent, 0 if rate limited
static inline __u8 can_send_event(void) {
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_ts = bpf_map_lookup_elem(&last_event_ts, &key);

    if (last_ts) {
        // Check if enough time has passed since last event
        if (now - *last_ts < EVENT_INTERVAL_NS) {
            return 0;  // Skip: rate limited
        }
    }

    // Update last event timestamp
    bpf_map_update_elem(&last_event_ts, &key, &now, BPF_ANY);
    return 1;  // Allow: send event
}

// Helper: check if IP is in allowed set
static inline int is_ip_allowed(__u32 ip) {
    __u8 *found = bpf_map_lookup_elem(&protected_ips, &ip);
    return found && *found == 1;
}

// Helper: check if port is in protected set
static inline int is_port_protected(__u16 port) {
    __u8 *found = bpf_map_lookup_elem(&protected_ports, &port);
    return found && *found == 1;
}

// TC ingress program - filters incoming packets
// Logic: Only allow traffic from IPs in the whitelist when accessing protected ports
SEC("tc/ingress")
int tc_ingress_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    // Check ethernet header
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    // Only process IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    // Get source IP (client IP sending the request)
    __u32 src_ip = ip->saddr;

    // Allow localhost without checking
    if (src_ip == LOCALHOST_IP) {  // 127.0.0.1 in network byte order
        return TC_ACT_OK;
    }

    // Get destination port
    __u16 dst_port_host = 0;   // Host byte order for map lookup
    __u16 dst_port_net = 0;    // Network byte order for event
    void *transport = ip + 1;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport;
        if (transport + sizeof(*tcp) <= data_end) {
            dst_port_net = tcp->dest;
            dst_port_host = bpf_ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport;
        if (transport + sizeof(*udp) <= data_end) {
            dst_port_net = udp->dest;
            dst_port_host = bpf_ntohs(udp->dest);
        }
    }

    // Check if destination port is protected
    if (dst_port_host != 0 && is_port_protected(dst_port_host)) {
        // Port is protected, check if source IP (client) is allowed
        if (!is_ip_allowed(src_ip)) {
            // Client IP not in whitelist - send event (rate-limited) and DROP
            if (can_send_event()) {
                struct drop_event event = {
                    .src_ip = src_ip,           // Already network byte order
                    .port = dst_port_host,      // Host byte order for correct display
                    .protocol = ip->protocol,
                    .dir = 0,  // ingress
                };
                bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
            }
            return TC_ACT_SHOT;
        }
    }

    // Either port not protected, or client IP is in whitelist - ALLOW
    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";

// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h> // Defines struct ethhdr
#include <linux/ip.h>       // Defines struct iphdr
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <linux/version.h>

#include <bpf/bpf_helpers.h>
#include <netinet/in.h>

#include <stdint.h>
#include <string.h>

#define MAX_DNS_NAME_LENGTH 256

char __license[] SEC("license") = "Dual MIT/GPL";

/*
                A unit array map to that is pinned to store and make changes to the additional
                latency added to the dns packets.
*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} latency SEC(".maps");

/*
                Hash map of all unique dns packets to their timestamp of exit.
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __uint16_t); // id of the dns_hdr
    __type(value, __u64);    // timestamp of the query
    __uint(max_entries, 1024);
} query_map SEC(".maps");

struct dns_query {
    __u8 name[MAX_DNS_NAME_LENGTH];
}; //__attribute__((packed));
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8[MAX_DNS_NAME_LENGTH]); // first query of dns packet
    __type(value, sizeof(__u32));           // exists or not
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} queryrecords SEC(".maps");

// map that allows kernel space to apply filter on dns packets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} enabledomain SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} enableserver SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} server_ip SEC(".maps");
//__u32 config_dns_server  =0;

struct dns_hdr {
    uint16_t id;
    uint8_t rd : 1;      // Recursion desired
    uint8_t tc : 1;      // Truncated
    uint8_t aa : 1;      // Authoritive answer
    uint8_t opcode : 4;  // Opcode
    uint8_t qr : 1;      // Query/response flag
    uint8_t rcode : 4;   // Response code
    uint8_t cd : 1;      // Checking disabled
    uint8_t ad : 1;      // Authenticated data
    uint8_t z : 1;       // Z reserved bit
    uint8_t ra : 1;      // Recursion available
    uint16_t q_count;    // Number of questions
    uint16_t ans_count;  // Number of answer RRs
    uint16_t auth_count; // Number of authority RRs
    uint16_t add_count;  // Number of resource RRs
};

/*
        We are using the ingress program to note the total latency taken for a dns packet and
        printing it in the form of a log so that user can see if the intended packets are affected.
*/
static void parse_query(struct __sk_buff *skb, void *query_start, struct dns_query *q) {
    void *data_end = (void *)(long)skb->data_end;
    void *cursor = query_start;
    int namepos = 0;
    uint8_t label_len = 0;
    char *char_cursor;

    // Zero out the name buffer
    memset(&q->name[0], 0, sizeof(q->name));

#pragma unroll

    for (int i = 0; i < 5; i++) {
        // Boundary check
        if (cursor + 1 > data_end)
            return;

        label_len = *(u_int8_t *)(cursor); // Read the length byte

        // Stop if we hit the end (0x00)
        if (label_len == 0) {
            return;
        }

        cursor++; // Move past the length byte

        // Copy label characters
        if (cursor + label_len > data_end) // Check bounds
            return;

        if (namepos + label_len >= (int)sizeof(q->name) - 1) // Avoid overflow
            return;
        if (label_len > 10) // Passes the verifier by restricting the read
        {
            label_len = 10;
        }
        // to ensure memory is read from dns format as characters into q.name
        char_cursor = (char *)cursor;

        bpf_probe_read_kernel(&q->name[namepos], label_len, char_cursor);

        namepos += label_len;
        q->name[namepos++] = '.'; // Insert a dot between labels

        cursor += label_len; // Move cursor forward
    }

    return;
}
SEC("tc")
int ingress_prog_func(struct __sk_buff *skb) {
    void *data_end = (void *)(unsigned long)skb->data_end;
    void *data = (void *)(unsigned long)skb->data;
    __u64 total_latency_ns;
    __u64 current_time_ns = bpf_ktime_get_ns();
    uint16_t id;

    // Boundary check: check if packet is larger than a full ethernet + ip header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;

    // Ignore packet if ethernet protocol is not IP-based
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = data + sizeof(*eth);

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        // Boundary check for UDP
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end) {
            return TC_ACT_OK;
        }

        udp = data + sizeof(*eth) + sizeof(*ip);

        if (udp->source == __constant_htons(53)) {
            // Boundary check for minimal DNS header
            if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dns_hdr) > data_end) {
                return TC_ACT_OK;
            }

            struct dns_hdr *dns_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
            if (dns_hdr->qr == 1) {
                id = dns_hdr->id;

                __u64 *query_ts = bpf_map_lookup_elem(&query_map, &id);
                if (query_ts != NULL) {

                    if (*query_ts < current_time_ns) {
                        total_latency_ns = current_time_ns - *query_ts;
                        bpf_printk("The total latency of the dns packet is : %u ms id :%u", total_latency_ns / 1000000,
                                   id);
                    }
                    bpf_map_delete_elem(&query_map, &id);
                }
            }
        }
    }
    return TC_ACT_OK;
}

SEC("tc")
int egress_prog_func(struct __sk_buff *skb) {
    __u32 zero = 0;
    __u64 *latency_ns;
    __u64 current_time_ns = bpf_ktime_get_ns();
    __u32 *domain_exists;
    void *data_end = (void *)(unsigned long)skb->data_end;
    void *data = (void *)(unsigned long)skb->data;
    struct dns_query q;
    __u32 *enable_domain;
    __u32 dest;
    __u32 *server_exists;
    __u32 *enable_server;

    // Boundary check: check if packet is larger than a full ethernet + ip header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;

    // Ignore packet if ethernet protocol is not IP-based
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = data + sizeof(*eth);

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        // Boundary check for UDP
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end) {
            return TC_ACT_OK;
        }

        udp = data + sizeof(*eth) + sizeof(*ip);

        if (udp->dest == __constant_htons(53)) {

            // Boundary check for minimal DNS header
            if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dns_hdr) > data_end) {
                return TC_ACT_OK;
            }

            struct dns_hdr *dns_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);

            uint16_t id = dns_hdr->id;
            bpf_printk("Egress: Dns packet recorded id: %u", id);
            bpf_map_update_elem(&query_map, &id, &current_time_ns, BPF_NOEXIST);

            // Check if url filter is enabled or not.
            enable_domain = bpf_map_lookup_elem(&enabledomain, &zero);

            if (enable_domain != NULL) {
                // bpf_printk("enable_domain value: %u\n", *enable_domain);
                if ((*enable_domain) == (__u32)1) {

                    void *query_start = (void *)dns_hdr + sizeof(struct dns_hdr);
                    // Find domain name of packet by parsing and storing in q.name
                    parse_query(skb, query_start, &q);

                    domain_exists = bpf_map_lookup_elem(&queryrecords, (q.name));
                    if (domain_exists == NULL) {
                        bpf_printk("FAILIURE Filtering Packet Domain Name : %s , id : %u", q.name, id);
                        return TC_ACT_OK;
                    } else {
                        bpf_printk("SUCCESS Filtering Packet Domain Name : %s , id : %u", q.name, id);
                    }
                }
            }
            enable_server = bpf_map_lookup_elem(&enableserver, &zero);

            if (enable_server != NULL) {
                // bpf_printk("enable_domain value: %u\n", *enable_domain);
                if ((*enable_server) == (__u32)1) {

                    dest = ip->daddr;
                    server_exists = bpf_map_lookup_elem(&server_ip, &dest);

                    if (server_exists == NULL) {
                        bpf_printk("FAILIURE : Filtering Packet Server Ip : %u , id : %u", dest, id);
                        return TC_ACT_OK;
                    } else {
                        bpf_printk("SUCCESS : Filtering Packet Server Ip : %u , id : %u", dest, id);
                    }
                }
            }
            // Finally if the packet is indeed a dns packet and passes all enabled filters
            // we will add the configured latency

            // Fetch latency from pinned map so that changes can appear dynamically
            latency_ns = bpf_map_lookup_elem(&latency, &zero);

            if (!latency_ns) {
                return 0;
            }
            // latency is added by manipulating the tstamp field.
            // Works only for fq discs, must replace q disc for this. Refer README.
            skb->tstamp = bpf_ktime_get_ns() + *latency_ns;
        }
    }

    return TC_ACT_OK;
}

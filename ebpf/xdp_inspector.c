// ebpf/xdp_inspector.c
// SPDX-License-Identifier: GPL-2.0
// Davide De Rubeis — ebpf-sentinel

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} packet_events SEC(".maps");

SEC("xdp")
int xdp_inspector(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct packet_event evt = {};
    evt.src_ip   = ip->saddr;
    evt.dst_ip   = ip->daddr;
    evt.protocol = ip->protocol;

    __u32 ip_header_size = ip->ihl * 4;

    // Controllo richiesto dal verifier eBPF: un header IP valido
    // e' sempre almeno 20 byte. Senza questo check il verifier
    // potrebbe rifiutare il programma su kernel piu' severi.
    if (ip_header_size < sizeof(struct iphdr))
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_header_size;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        evt.src_port = bpf_ntohs(tcp->source);
        evt.dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_header_size;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        evt.src_port = bpf_ntohs(udp->source);
        evt.dst_port = bpf_ntohs(udp->dest);
    }

    bpf_perf_event_output(ctx, &packet_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
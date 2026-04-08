// ebpf/xdp_blocker.c
// SPDX-License-Identifier: GPL-2.0
// Davide De Rubeis — ebpf-sentinel
//
// Programma XDP con blacklist dinamica.
// Gli IP da bloccare vengono inseriti nella mappa ip_blacklist
// dallo user space (loader.c) senza ricompilare questo file.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Struttura evento — aggiunto il campo "blocked"
// rispetto alla Parte 5.
// ATTENZIONE: deve essere identica alla stessa struttura
// definita in loader.c, altrimenti i dati letti
// dallo user space saranno corrotti.
struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  blocked;   // 1 = pacchetto bloccato, 0 = accettato
};

// Mappa hash per la blacklist degli IP.
// Chiave: indirizzo IP sorgente in network byte order (__u32)
// Valore: __u32 con valore 1 (presenza nella blacklist)
// max_entries: numero massimo di IP bloccabili contemporaneamente
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} ip_blacklist SEC(".maps");

// Mappa perf per inviare eventi allo user space.
// Identica a quella della Parte 5.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} packet_events SEC(".maps");

SEC("xdp")
int xdp_blocker(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ── Header Ethernet ─────────────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // ── Header IP ───────────────────────────────────────────────────
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 ip_header_size = ip->ihl * 4;
    if (ip_header_size < sizeof(struct iphdr))
        return XDP_PASS;

    // Prepariamo l'evento con i dati comuni a tutti i pacchetti.
    struct packet_event evt = {};
    evt.src_ip   = ip->saddr;
    evt.dst_ip   = ip->daddr;
    evt.protocol = ip->protocol;
    evt.blocked  = 0;

    // ── Header TCP / UDP ─────────────────────────────────────────────
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

    // ── Controllo blacklist ──────────────────────────────────────────
    // bpf_map_lookup_elem restituisce un puntatore al valore
    // associato alla chiave, oppure NULL se la chiave non esiste.
    // ip->saddr è già in network byte order: corrisponde esattamente
    // alle chiavi inserite dallo user space tramite inet_pton().
    __u32 *blacklisted = bpf_map_lookup_elem(&ip_blacklist, &ip->saddr);

    if (blacklisted) {
        // IP in blacklist: marchiamo l'evento e blocchiamo.
        evt.blocked = 1;
        bpf_perf_event_output(ctx, &packet_events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
        return XDP_DROP;
    }

    // IP non in blacklist: inviamo l'evento e lasciamo passare.
    bpf_perf_event_output(ctx, &packet_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
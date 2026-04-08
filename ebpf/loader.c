// ebpf/loader.c
// SPDX-License-Identifier: MIT
// Davide De Rubeis — ebpf-sentinel

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_inspector.skel.h"

struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

static volatile int running = 1;

void handle_signal(int sig) {
    running = 0;
}

void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    // Verifica che l'evento ricevuto abbia la dimensione attesa.
    // Protegge da eventi corrotti o troncati.
    if (size < sizeof(struct packet_event))
        return;

    struct packet_event *evt = data;

    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &evt->src_ip, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &evt->dst_ip, dst_str, sizeof(dst_str));

    const char *proto;
    switch (evt->protocol) {
        case IPPROTO_TCP:  proto = "TCP";  break;
        case IPPROTO_UDP:  proto = "UDP";  break;
        case IPPROTO_ICMP: proto = "ICMP"; break;
        default:           proto = "???";  break;
    }

    printf("[ebpf-sentinel] %s  %s:%u  ->  %s:%u\n",
           proto, src_str, evt->src_port, dst_str, evt->dst_port);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <interfaccia di rete>\n", argv[0]);
        fprintf(stderr, "Esempio: %s eth0\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    struct xdp_inspector *skel = xdp_inspector__open_and_load();
    if (!skel) {
        fprintf(stderr, "Errore nel caricamento del programma eBPF\n");
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Interfaccia '%s' non trovata\n", ifname);
        xdp_inspector__destroy(skel);
        return 1;
    }

    if (bpf_xdp_attach(ifindex,
                        bpf_program__fd(skel->progs.xdp_inspector),
                        XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "Errore nell'aggancio XDP: %s\n", strerror(errno));
        xdp_inspector__destroy(skel);
        return 1;
    }

    printf("[ebpf-sentinel] In ascolto su '%s'. Premi Ctrl+C per uscire.\n\n",
           ifname);

    struct perf_buffer *pb = perf_buffer__new(
        bpf_map__fd(skel->maps.packet_events),
        8,
        handle_event,
        NULL,
        NULL,
        NULL
    );

    if (!pb) {
        fprintf(stderr, "Errore nella creazione del perf buffer\n");
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        xdp_inspector__destroy(skel);
        return 1;
    }

    while (running) {
        perf_buffer__poll(pb, 100);
    }

    printf("\n[ebpf-sentinel] Uscita. Rimozione programma XDP...\n");
    perf_buffer__free(pb);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    xdp_inspector__destroy(skel);

    return 0;
}
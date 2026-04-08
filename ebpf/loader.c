// ebpf/loader.c
// SPDX-License-Identifier: MIT
// Davide De Rubeis — ebpf-sentinel
//
// Uso:
//   sudo ./sentinel <interfaccia> [-b <IP_da_bloccare>] ...
//   sudo ./sentinel eth0 -b 8.8.8.8 -b 1.2.3.4

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_blocker.skel.h"   // skeleton del nuovo programma

// Struttura evento — identica a quella in xdp_blocker.c.
// Qualsiasi modifica va applicata in entrambi i file.
struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  blocked;
};

static volatile int running = 1;

void handle_signal(int sig) {
    running = 0;
}

void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    // Protezione da eventi di dimensione inattesa o corrotti.
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

    // I pacchetti bloccati vengono evidenziati con [BLOCKED].
    if (evt->blocked) {
        printf("[ebpf-sentinel] [BLOCKED] %s  %s:%u  ->  %s:%u\n",
               proto, src_str, evt->src_port, dst_str, evt->dst_port);
    } else {
        printf("[ebpf-sentinel] [PASS]    %s  %s:%u  ->  %s:%u\n",
               proto, src_str, evt->src_port, dst_str, evt->dst_port);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <interfaccia> [-b <IP>] ...\n", argv[0]);
        fprintf(stderr, "Es.: %s eth0 -b 8.8.8.8 -b 1.2.3.4\n", argv[0]);
        return 1;
    }

    // Parsing degli argomenti.
    // Il primo argomento non preceduto da -b è l'interfaccia.
    // Gli argomenti -b <IP> sono gli IP da bloccare.
    const char *ifname = NULL;
    __u32 blocked_ips[256];
    int   n_blocked = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            struct in_addr addr;
            if (inet_pton(AF_INET, argv[i + 1], &addr) != 1) {
                fprintf(stderr, "IP non valido: %s\n", argv[i + 1]);
                return 1;
            }
            if (n_blocked >= 256) {
                fprintf(stderr, "Troppi IP: massimo 256\n");
                return 1;
            }
            // addr.s_addr è già in network byte order,
            // come ip->saddr nel programma eBPF. Nessuna conversione
            // aggiuntiva necessaria.
            blocked_ips[n_blocked++] = addr.s_addr;
            i++;
        } else if (!ifname) {
            ifname = argv[i];
        }
    }

    if (!ifname) {
        fprintf(stderr, "Interfaccia non specificata\n");
        return 1;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    // ── Caricamento del programma eBPF ───────────────────────────────
    struct xdp_blocker *skel = xdp_blocker__open_and_load();
    if (!skel) {
        fprintf(stderr, "Errore nel caricamento del programma eBPF\n");
        return 1;
    }

    // ── Aggancio all'interfaccia ─────────────────────────────────────
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Interfaccia '%s' non trovata\n", ifname);
        xdp_blocker__destroy(skel);
        return 1;
    }

    if (bpf_xdp_attach(ifindex,
                        bpf_program__fd(skel->progs.xdp_blocker),
                        XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "Errore nell'aggancio XDP: %s\n", strerror(errno));
        xdp_blocker__destroy(skel);
        return 1;
    }

    // ── Popolamento della blacklist ──────────────────────────────────
    // bpf_map_update_elem inserisce o aggiorna una coppia chiave/valore
    // nella mappa. BPF_ANY significa: inserisci se non esiste,
    // aggiorna se esiste già.
    int map_fd = bpf_map__fd(skel->maps.ip_blacklist);
    __u32 value = 1;

    for (int i = 0; i < n_blocked; i++) {
        if (bpf_map_update_elem(map_fd, &blocked_ips[i],
                                &value, BPF_ANY) < 0) {
            fprintf(stderr, "Errore nell'aggiunta dell'IP alla blacklist\n");
            bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
            xdp_blocker__destroy(skel);
            return 1;
        }
        // Stampiamo gli IP bloccati in formato leggibile.
        char ip_str[INET_ADDRSTRLEN];
        struct in_addr addr = { .s_addr = blocked_ips[i] };
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        printf("[ebpf-sentinel] IP bloccato: %s\n", ip_str);
    }

    printf("[ebpf-sentinel] In ascolto su '%s'. Premi Ctrl+C per uscire.\n\n",
           ifname);

    // ── Loop di lettura eventi ───────────────────────────────────────
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
        xdp_blocker__destroy(skel);
        return 1;
    }

    while (running) {
        perf_buffer__poll(pb, 100);
    }

    // ── Pulizia ──────────────────────────────────────────────────────
    printf("\n[ebpf-sentinel] Uscita. Rimozione programma XDP...\n");
    perf_buffer__free(pb);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    xdp_blocker__destroy(skel);

    return 0;
}
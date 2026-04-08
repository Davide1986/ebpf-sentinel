// ebpf/loader.c
// SPDX-License-Identifier: MIT
// Davide De Rubeis — ebpf-sentinel
// Loader: carica il programma XDP nel kernel e legge gli eventi.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>          // inet_ntop
#include <bpf/libbpf.h>         // API libbpf
#include <bpf/bpf.h>
#include "xdp_inspector.skel.h" // Generato automaticamente da libbpf

// Struttura evento — deve essere identica a quella in xdp_inspector.c
struct packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

// Flag per gestire l'uscita pulita con Ctrl+C
static volatile int running = 1;

void handle_signal(int sig) {
    running = 0;
}

// Questa funzione viene chiamata da libbpf ogni volta che
// arriva un evento dalla mappa perf. È il nostro punto
// di ingresso per analizzare i pacchetti lato user space.
void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct packet_event *evt = data;

    // Convertiamo gli indirizzi IP in stringhe leggibili
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &evt->src_ip, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &evt->dst_ip, dst_str, sizeof(dst_str));

    // Determiniamo il nome del protocollo
    const char *proto;
    switch (evt->protocol) {
        case IPPROTO_TCP:  proto = "TCP";  break;
        case IPPROTO_UDP:  proto = "UDP";  break;
        case IPPROTO_ICMP: proto = "ICMP"; break;
        default:           proto = "???";  break;
    }

    printf("[ebpf-sentinel] %s  %s:%u  →  %s:%u\n",
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

    // Registriamo il gestore per Ctrl+C
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    // ── Step 1: Carica il programma eBPF ─────────────────────────────
    // xdp_inspector__open_and_load() è generata automaticamente
    // dallo skeleton libbpf a partire dal nostro .c kernel.
    // Si occupa di aprire il file oggetto, verificarlo e caricarlo.
    struct xdp_inspector *skel = xdp_inspector__open_and_load();
    if (!skel) {
        fprintf(stderr, "Errore nel caricamento del programma eBPF\n");
        return 1;
    }

    // ── Step 2: Aggancia il programma all'interfaccia ─────────────────
    // Otteniamo l'indice dell'interfaccia di rete specificata
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Interfaccia '%s' non trovata\n", ifname);
        xdp_inspector__destroy(skel);
        return 1;
    }

    // Colleghiamo il programma XDP all'interfaccia.
    // XDP_FLAGS_SKB_MODE è la modalità compatibile con tutte
    // le schede di rete, incluse quelle virtualizzate.
    // Nelle prossime parti vedremo anche XDP_FLAGS_DRV_MODE,
    // la modalità nativa che offre prestazioni ancora migliori.
    if (bpf_xdp_attach(ifindex,
                        bpf_program__fd(skel->progs.xdp_inspector),
                        XDP_FLAGS_SKB_MODE, NULL) < 0) {
        fprintf(stderr, "Errore nell'aggancio XDP: %s\n", strerror(errno));
        xdp_inspector__destroy(skel);
        return 1;
    }

    printf("[ebpf-sentinel] In ascolto su '%s'. Premi Ctrl+C per uscire.\n\n",
           ifname);

    // ── Step 3: Leggi gli eventi in loop ─────────────────────────────
    // perf_buffer__new crea un buffer per leggere gli eventi
    // dalla mappa perf in modo efficiente.
    struct perf_buffer *pb = perf_buffer__new(
        bpf_map__fd(skel->maps.packet_events),
        8,            // Numero di pagine per CPU
        handle_event, // Funzione chiamata per ogni evento
        NULL,         // Funzione per eventi persi (opzionale)
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
        // perf_buffer__poll attende eventi per 100ms.
        // Se arrivano eventi, chiama handle_event per ognuno.
        perf_buffer__poll(pb, 100);
    }

    // ── Pulizia ───────────────────────────────────────────────────────
    printf("\n[ebpf-sentinel] Uscita. Rimozione programma XDP...\n");
    perf_buffer__free(pb);
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    xdp_inspector__destroy(skel);

    return 0;
}
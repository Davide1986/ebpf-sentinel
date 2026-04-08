// ebpf/xdp_inspector.c
// SPDX-License-Identifier: MIT
// Davide De Rubeis — ebpf-sentinel
// Programma XDP: ispeziona ogni pacchetto prima che salga nello stack di rete.

#include <linux/bpf.h>
#include <linux/if_ether.h>   // struct ethhdr — header Ethernet
#include <linux/ip.h>         // struct iphdr  — header IPv4
#include <linux/tcp.h>        // struct tcphdr — header TCP
#include <linux/udp.h>        // struct udphdr — header UDP
#include <bpf/bpf_helpers.h>  // bpf_printk, bpf_map_lookup_elem, ecc.
#include <arpa/inet.h>        // ntohs, ntohl — conversione byte order

// Struttura che rappresenta un evento da inviare allo user space.
// Per ogni pacchetto rilevante, riempiamo questa struttura
// e la scriviamo nella mappa.
struct packet_event {
    __u32 src_ip;       // Indirizzo IP sorgente
    __u32 dst_ip;       // Indirizzo IP destinazione
    __u16 src_port;     // Porta sorgente (0 se non è TCP/UDP)
    __u16 dst_port;     // Porta destinazione (0 se non è TCP/UDP)
    __u8  protocol;     // Protocollo: IPPROTO_TCP, IPPROTO_UDP, ecc.
};

// Definiamo la mappa eBPF di tipo PERF_EVENT_ARRAY.
// Questo tipo di mappa permette di inviare eventi dallo spazio kernel
// allo spazio utente in modo efficiente, usando il meccanismo
// perf_event del kernel. È la scelta giusta per flussi di eventi
// continui come il traffico di rete.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} packet_events SEC(".maps");

// SEC("xdp") dice al compilatore di mettere questa funzione
// nella sezione ELF chiamata "xdp". libbpf userà questa
// informazione per capire che tipo di programma è e dove agganciarlo.
SEC("xdp")
int xdp_inspector(struct xdp_md *ctx)
{
    // ctx->data e ctx->data_end sono i puntatori all'inizio
    // e alla fine del pacchetto in memoria.
    // Il verifier eBPF ci obbliga a controllare sempre i limiti
    // prima di accedere ai dati — altrimenti rifiuta il programma.
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ── Step 1: Header Ethernet ──────────────────────────────────────
    struct ethhdr *eth = data;

    // Controllo fondamentale dei limiti: se l'header Ethernet non
    // ci sta nel pacchetto, lo lasciamo passare senza analizzarlo.
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Ci interessa solo IPv4 (0x0800).
    // Per ora ignoriamo ARP, IPv6 e altri protocolli.
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // ── Step 2: Header IP ────────────────────────────────────────────
    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Prepariamo l'evento da inviare allo user space.
    struct packet_event evt = {};
    evt.src_ip   = ip->saddr;
    evt.dst_ip   = ip->daddr;
    evt.protocol = ip->protocol;

    // ── Step 3: Header TCP o UDP ─────────────────────────────────────
    // ihl (IP Header Length) contiene la lunghezza dell'header IP
    // in unità da 4 byte. Moltiplichiamo per 4 per ottenere i byte.
    __u32 ip_header_size = ip->ihl * 4;

    if (ip->protocol == IPPROTO_TCP) {

        struct tcphdr *tcp = (void *)ip + ip_header_size;

        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        evt.src_port = ntohs(tcp->source);
        evt.dst_port = ntohs(tcp->dest);

    } else if (ip->protocol == IPPROTO_UDP) {

        struct udphdr *udp = (void *)ip + ip_header_size;

        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        evt.src_port = ntohs(udp->source);
        evt.dst_port = ntohs(udp->dest);
    }

    // ── Step 4: Invia l'evento allo user space ───────────────────────
    // bpf_perf_event_output scrive l'evento nella mappa.
    // BPF_F_CURRENT_CPU indica di usare il buffer del core
    // su cui sta girando questo programma — ottimizzazione
    // importante su sistemi multicore.
    bpf_perf_event_output(ctx, &packet_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));

    // ── Step 5: Lascia passare il pacchetto ──────────────────────────
    // Per ora accettiamo tutto. Nelle prossime parti
    // decideremo qui se bloccare il pacchetto (XDP_DROP)
    // in base all'analisi dell'AI.
    return XDP_PASS;
}

// Obbligatorio: indica la licenza del programma.
// Il kernel accetta solo programmi GPL-compatibili.
char _license[] SEC("license") = "GPL";
// ebpf/syscall_tracer.c
// SPDX-License-Identifier: GPL-2.0
// Davide De Rubeis — ebpf-sentinel
//
// Tracepoint su sys_enter_connect:
// intercetta ogni chiamata connect() e registra
// quale processo si sta connettendo e verso dove.

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// Struttura sockaddr_in minimale — necessaria per leggere
// l'indirizzo IP di destinazione dalla chiamata connect().
// Non includiamo sys/socket.h perché non è disponibile
// lato eBPF kernel. Definiamo solo quello che ci serve.
struct sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
};

// Struttura evento inviata allo user space.
struct syscall_event {
    __u32 pid;              // PID del processo
    __u32 dst_ip;           // IP di destinazione
    __u16 dst_port;         // Porta di destinazione
    char  comm[16];         // Nome del processo (max 16 caratteri)
};

// Mappa perf per inviare eventi allo user space.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} syscall_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct syscall_event evt = {};

    // bpf_get_current_pid_tgid restituisce un valore a 64 bit:
    // i 32 bit alti sono il PID del processo,
    // i 32 bit bassi sono il TID del thread.
    evt.pid = bpf_get_current_pid_tgid() >> 32;

    // Copia il nome del processo nel buffer comm.
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // Leggiamo la struttura sockaddr passata dal processo.
    // Usiamo bpf_probe_read_user perché il puntatore
    // punta a memoria dello user space.
    struct sockaddr_in addr = {};
    if (bpf_probe_read_user(&addr, sizeof(addr),
                             (void *)ctx->args[1]) < 0)
        return 0;

    // Ci interessano solo le connessioni IPv4 (AF_INET = 2).
    if (addr.sin_family != 2)
        return 0;

    evt.dst_ip   = addr.sin_addr;
    evt.dst_port = bpf_ntohs(addr.sin_port);

    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));

    return 0;
}

char _license[] SEC("license") = "GPL";
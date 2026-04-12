// ebpf/syscall_tracer.c
// SPDX-License-Identifier: GPL-2.0
// Davide De Rubeis — ebpf-sentinel

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// Struttura evento inviata allo user space.
struct syscall_event {
    __u32 pid;
    __u32 dst_ip;
    __u16 dst_port;
    char  comm[16];
};

// Mappa perf per inviare eventi allo user space.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} syscall_events SEC(".maps");

// Struttura degli argomenti del tracepoint sys_enter_connect.
// Definita qui direttamente per evitare dipendenze
// da vmlinux.h o header non disponibili lato eBPF.
struct sys_enter_connect_args {
    unsigned long long unused;
    long               syscall_nr;
    long               fd;
    // Puntatore alla struttura sockaddr passata da user space
    struct {
        __u16 sin_family;
        __u16 sin_port;
        __u32 sin_addr;
    } __attribute__((packed)) *uservaddr;
    int                addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct sys_enter_connect_args *ctx)
{
    struct syscall_event evt = {};

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // Struttura sockaddr minimale per la lettura
    struct {
        __u16 sin_family;
        __u16 sin_port;
        __u32 sin_addr;
    } addr = {};

    if (bpf_probe_read_user(&addr, sizeof(addr),
                             ctx->uservaddr) < 0)
        return 0;

    // Solo IPv4 (AF_INET = 2)
    if (addr.sin_family != 2)
        return 0;

    evt.dst_ip   = addr.sin_addr;
    evt.dst_port = bpf_ntohs(addr.sin_port);

    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));
    return 0;
}

char _license[] SEC("license") = "GPL";
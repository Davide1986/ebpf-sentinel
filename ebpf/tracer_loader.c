// ebpf/tracer_loader.c
// SPDX-License-Identifier: MIT
// Davide De Rubeis — ebpf-sentinel

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include "syscall_tracer.skel.h"

struct syscall_event {
    __u32 pid;
    __u32 dst_ip;
    __u16 dst_port;
    char  comm[16];
};

static volatile int running = 1;

void handle_signal(int sig) {
    running = 0;
}

void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    if (size < sizeof(struct syscall_event))
        return;

    struct syscall_event *evt = data;

    char dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &evt->dst_ip, dst_str, sizeof(dst_str));

    printf("[tracer] PID: %-6u  PROC: %-16s  ->  %s:%u\n",
           evt->pid, evt->comm, dst_str, evt->dst_port);
}

int main(void)
{
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    struct syscall_tracer *skel = syscall_tracer__open_and_load();
    if (!skel) {
        fprintf(stderr, "Errore nel caricamento del tracer eBPF\n");
        return 1;
    }

    if (syscall_tracer__attach(skel) < 0) {
        fprintf(stderr, "Errore nell'aggancio al tracepoint\n");
        syscall_tracer__destroy(skel);
        return 1;
    }

    printf("[tracer] In ascolto sulle chiamate connect(). "
           "Premi Ctrl+C per uscire.\n\n");

    struct perf_buffer *pb = perf_buffer__new(
        bpf_map__fd(skel->maps.syscall_events),
        8,
        handle_event,
        NULL,
        NULL,
        NULL
    );

    if (!pb) {
        fprintf(stderr, "Errore nella creazione del perf buffer\n");
        syscall_tracer__destroy(skel);
        return 1;
    }

    while (running) {
        perf_buffer__poll(pb, 100);
    }

    printf("\n[tracer] Uscita.\n");
    perf_buffer__free(pb);
    syscall_tracer__destroy(skel);

    return 0;
}
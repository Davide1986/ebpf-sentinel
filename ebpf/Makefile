# ebpf/Makefile
# SPDX-License-Identifier: MIT
# Davide De Rubeis — ebpf-sentinel
#
# REQUISITI (Ubuntu 24.04):
#   sudo apt install clang llvm libbpf-dev \
#        linux-tools-$(uname -r) linux-tools-common \
#        build-essential
#
# Versioni minime: clang >= 12, libbpf >= 0.5, kernel >= 5.10
#
# Uso:
#   make                 compila tutto
#   make clean           rimuove i file generati
#   make run IFACE=eth0  esegue il firewall
#   make run IFACE=eth0 BLOCK="8.8.8.8 1.2.3.4"  blocca IP
#   make trace           esegue il tracer syscall

ARCH          := $(shell uname -m)
KERN_INCLUDES := -I/usr/include/$(ARCH)-linux-gnu
BPF_CFLAGS    := -O2 -g -target bpf $(KERN_INCLUDES)
USER_CFLAGS   := -O2 -Wall
LIBS          := -lbpf
TARGET        := sentinel
TRACER        := tracer

.PHONY: all clean run trace

all: $(TARGET) $(TRACER)

xdp_blocker.o: xdp_blocker.c
	clang $(BPF_CFLAGS) -c $< -o $@

xdp_blocker.skel.h: xdp_blocker.o
	bpftool gen skeleton $< > $@

$(TARGET): loader.c xdp_blocker.skel.h
	gcc $(USER_CFLAGS) -o $@ $< $(LIBS)

syscall_tracer.o: syscall_tracer.c
	clang $(BPF_CFLAGS) -c $< -o $@

syscall_tracer.skel.h: syscall_tracer.o
	bpftool gen skeleton $< > $@

$(TRACER): tracer_loader.c syscall_tracer.skel.h
	gcc $(USER_CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f xdp_blocker.o xdp_blocker.skel.h $(TARGET)
	rm -f syscall_tracer.o syscall_tracer.skel.h $(TRACER)

run: $(TARGET)
	@if [ -z "$(IFACE)" ]; then \
		echo "Specifica l'interfaccia: make run IFACE=eth0"; \
		exit 1; \
	fi
	sudo ./$(TARGET) $(IFACE)

trace: $(TRACER)
	sudo ./$(TRACER)
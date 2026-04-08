# ebpf/Makefile
# SPDX-License-Identifier: MIT
# Davide De Rubeis — ebpf-sentinel
#
# REQUISITI (Ubuntu 22.04 / Debian 12):
#   sudo apt install clang llvm libbpf-dev bpftool \
#                    linux-headers-$(uname -r) build-essential
#
# Versioni minime: clang >= 12, libbpf >= 0.5, kernel >= 5.10
# Nota: il percorso degli header e' valido su Debian/Ubuntu.
#       Su altre distribuzioni potrebbe essere /usr/include/linux
#
# Uso:
#   make                        compila tutto
#   make clean                  rimuove i file generati
#   make run IFACE=eth0         esegue senza bloccare nulla
#   make run IFACE=eth0 BLOCK="8.8.8.8 1.2.3.4"  blocca IP

ARCH          := $(shell uname -m)
KERN_INCLUDES := -I/usr/include/$(ARCH)-linux-gnu
BPF_CFLAGS    := -O2 -g -target bpf $(KERN_INCLUDES)
USER_CFLAGS   := -O2 -Wall
LIBS          := -lbpf
TARGET        := sentinel

.PHONY: all clean run

all: $(TARGET)

xdp_blocker.o: xdp_blocker.c
	clang $(BPF_CFLAGS) -c $< -o $@

xdp_blocker.skel.h: xdp_blocker.o
	bpftool gen skeleton $< > $@

$(TARGET): loader.c xdp_blocker.skel.h
	gcc $(USER_CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f xdp_blocker.o xdp_blocker.skel.h $(TARGET)

run: $(TARGET)
	@if [ -z "$(IFACE)" ]; then \
		echo "Specifica l'interfaccia: make run IFACE=eth0"; \
		exit 1; \
	fi
	@BLOCK_ARGS=""; \
	for ip in $(BLOCK); do \
		BLOCK_ARGS="$$BLOCK_ARGS -b $$ip"; \
	done; \
	sudo ./$(TARGET) $(IFACE) $$BLOCK_ARGS
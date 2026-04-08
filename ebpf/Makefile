# ebpf/Makefile
# SPDX-License-Identifier: MIT
# Davide De Rubeis — ebpf-sentinel
#
# REQUISITI:
#   sudo apt install clang llvm libbpf-dev bpftool linux-headers-$(uname -r)
#
# Testato su: Ubuntu 22.04, Debian 12, kernel >= 5.10
# Nota: su architetture o kernel diversi potrebbe essere necessario
# generare vmlinux.h da BTF. Vedere docs/ per istruzioni.
#
# Uso:
#   make          → compila tutto
#   make clean    → rimuove i file generati
#   make run IFACE=eth0 → esegue il programma

# Rileva automaticamente l'architettura della macchina
ARCH := $(shell uname -m)

# Include gli header del kernel per l'architettura corrente
KERN_INCLUDES := -I/usr/include/$(ARCH)-linux-gnu

# Flags per la compilazione del programma eBPF (kernel side)
# -O2           ottimizzazione necessaria per eBPF
# -g            informazioni di debug (utile con bpftool)
# -target bpf   dice a clang di produrre bytecode eBPF
BPF_CFLAGS := -O2 -g -target bpf $(KERN_INCLUDES)

# Flags per la compilazione del loader (user side)
USER_CFLAGS := -O2 -Wall

# Librerie necessarie per il loader
LIBS := -lbpf

# Nome del binario finale
TARGET := sentinel

.PHONY: all clean run

# Target principale: compila tutto nella sequenza corretta
all: $(TARGET)

# Step 1: compila xdp_inspector.c in bytecode eBPF (.o)
xdp_inspector.o: xdp_inspector.c
	clang $(BPF_CFLAGS) -c $< -o $@

# Step 2: genera lo skeleton (.skel.h) dal bytecode
# Questo file viene incluso dal loader e contiene
# le funzioni per caricare e gestire il programma eBPF
xdp_inspector.skel.h: xdp_inspector.o
	bpftool gen skeleton $< > $@

# Step 3: compila il loader usando lo skeleton appena generato
$(TARGET): loader.c xdp_inspector.skel.h
	gcc $(USER_CFLAGS) -o $@ $< $(LIBS)

# Rimuove tutti i file generati dalla compilazione
clean:
	rm -f xdp_inspector.o xdp_inspector.skel.h $(TARGET)

# Esegue il programma — specifica l'interfaccia con IFACE=eth0
# Esempio: make run IFACE=eth0
run: $(TARGET)
	@if [ -z "$(IFACE)" ]; then \
		echo "Specifica l'interfaccia: make run IFACE=eth0"; \
		exit 1; \
	fi
	sudo ./$(TARGET) $(IFACE)
# ebpf-sentinel

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-blue.svg)]()
[![Language](https://img.shields.io/badge/language-C%20%7C%20Python-orange.svg)]()
[![Status](https://img.shields.io/badge/status-in%20sviluppo-yellow.svg)]()

Un EDR (Endpoint Detection & Response) leggero per Linux, costruito passo dopo
passo a scopo educativo e di ricerca.

Sfrutta **eBPF** per l'ispezione dei pacchetti di rete in tempo reale,
un **memory scanner** per rilevare codice malevolo in memoria e un motore
di **anomaly detection basato su AI** per bloccare le minacce prima che
causino danni.

---

## Struttura del progetto
ebpf-sentinel/
├── ebpf/        # Programmi eBPF (kernel side) e loader libbpf (user side)
├── ai/          # Modello di anomaly detection (Isolation Forest → ONNX)
├── memory/      # Memory scanner: analisi di /proc/PID/maps e /proc/PID/mem
├── agent/       # Collector: raccoglie eventi da eBPF e li passa all'AI
├── edr/         # Core orchestratore: mette insieme tutti i moduli
└── docs/        # Documentazione, schemi e riferimenti

---

## Serie di articoli

Questo progetto è costruito pubblicamente, articolo per articolo, su LinkedIn.

| Parte | Argomento |
|-------|-----------|
| 1 | Introduzione a NFQUEUE e Netfilter |
| 2 | libnetfilter_queue: architettura e librerie |
| 3 | Progettazione del flusso e della Callback |
| 4 | Codice della Callback e introduzione a eBPF |
| 5 | eBPF: primo programma XDP *(in arrivo)* |
| 6 | eBPF + AI: anomaly detection sui pacchetti |
| 7 | I pacchetti invisibili a eBPF: TLS, tunneling |
| 8 | Memory scanner: /proc e pattern matching |
| 9 | EDR completo: tutto integrato |

---

## Requisiti minimi

- Linux kernel >= 5.10
- Clang >= 12 e libbpf
- Python >= 3.9 (per il modulo AI)
- 2 GB RAM (testato in macchina virtuale)

---

## Come contribuire

Il progetto è aperto a contributi di ogni tipo: correzioni, miglioramenti
al codice, traduzione della documentazione, test su distribuzioni diverse.

Apri una **Issue** per segnalare un problema o proporre un'idea,
oppure invia una **Pull Request** direttamente.

---

## Autore

**Davide De Rubeis**
Sistemista e Amministratore Reti — Istituto CEFI
Laureato in Ingegneria Informatica — Università degli Studi di Roma Tre

---

## Licenza

Distribuito sotto licenza [MIT](LICENSE).
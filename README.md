# ebpf-sentinel

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-blue.svg)]()
[![Language](https://img.shields.io/badge/language-C%20%7C%20Python-orange.svg)]()
[![Status](https://img.shields.io/badge/status-in%20sviluppo-yellow.svg)]()

---

## 🛡️ Cos'è ebpf-sentinel

**ebpf-sentinel** è un EDR (Endpoint Detection & Response) leggero per Linux,
costruito passo dopo passo a scopo educativo e di ricerca.

Il progetto sfrutta:

* 🔍 **eBPF** → ispezione dei pacchetti di rete in tempo reale
* 🧠 **AI (Anomaly Detection)** → rilevamento comportamenti sospetti
* 🧬 **Memory Scanner** → analisi della memoria per codice malevolo

L’obiettivo è bloccare le minacce prima che causino danni.

---

## 📁 Struttura del progetto

```bash
ebpf-sentinel/
├── ebpf/        # Programmi eBPF (kernel) + loader libbpf (user)
├── ai/          # Modello anomaly detection (Isolation Forest → ONNX)
├── memory/      # Scanner memoria (/proc/PID/maps e /proc/PID/mem)
├── agent/       # Collector eventi eBPF → AI
├── edr/         # Core orchestratore
└── docs/        # Documentazione e schemi
```

---

## 📚 Serie di articoli

Il progetto è sviluppato pubblicamente su LinkedIn.

| Parte | Argomento                                   |
| ----: | ------------------------------------------- |
|     1 | Introduzione a NFQUEUE e Netfilter          |
|     2 | libnetfilter_queue: architettura e librerie |
|     3 | Progettazione del flusso e della callback   |
|     4 | Codice della callback + introduzione a eBPF |
|     5 | eBPF: primo programma XDP *(in arrivo)*     |
|     6 | eBPF + AI: anomaly detection sui pacchetti  |
|     7 | Limiti eBPF: TLS e tunneling                |
|     8 | Memory scanner: `/proc` e pattern matching  |
|     9 | EDR completo: integrazione finale           |

---

## ⚙️ Requisiti

* 🐧 Linux kernel **>= 5.10**
* 🛠️ Clang **>= 12** + libbpf
* 🐍 Python **>= 3.9**
* 💾 RAM: minimo **2 GB** (testato in VM)

---

## 🤝 Come contribuire

Contributi benvenuti!

* 🐛 Segnala bug aprendo una **Issue**
* 💡 Proponi miglioramenti
* 🔧 Invia una **Pull Request**
* 🌍 Aiuta con traduzioni o test

---

## 👨‍💻 Autore

**Davide De Rubeis**
Sistemista & Amministratore di Rete — Istituto CEFI
Laureato in Ingegneria Informatica — Università Roma Tre

---

## 📄 Licenza

Distribuito sotto licenza [MIT](LICENSE).

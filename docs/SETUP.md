# ⚙️ Setup e installazione

Guida passo passo per compilare e testare **ebpf-sentinel**
su una macchina virtuale o un server dedicato.

---

## 📋 Requisiti

| Componente        | Versione minima  |
| ----------------- | ---------------- |
| Sistema operativo | Ubuntu 24.04 LTS |
| Kernel Linux      | >= 5.10          |
| clang             | >= 12            |
| libbpf            | >= 0.5           |
| bpftool           | versione recente |

> ✅ Testato su DigitalOcean (Ubuntu 24.04, 1 vCPU, 2 GB RAM)
> Configurazione sufficiente per tutti i test.

---

## 🧰 1. Preparazione del sistema

Aggiorna il sistema e installa le dipendenze:

```bash
sudo apt update && sudo apt install -y \
    clang llvm libbpf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    linux-tools-common \
    build-essential git
```

Verifica l’installazione:

```bash
clang --version
bpftool version
```

Output atteso (esempio):

```text
Ubuntu clang version 18.x
bpftool v7.x
using libbpf v1.x
```

---

## 📥 2. Clona il repository

```bash
git clone https://github.com/Davide1986/ebpf-sentinel.git
cd ebpf-sentinel/ebpf
```

---

## 🏗️ 3. Compilazione

```bash
make
```

Il processo esegue:

1. Compilazione eBPF (`xdp_blocker.c`)
2. Generazione skeleton (`bpftool`)
3. Build del loader (`loader.c`)

Output tipico:

```text
clang -O2 -g -target bpf ...
bpftool gen skeleton ...
gcc -O2 -Wall -o sentinel ...
```

---

## 🚀 4. Esecuzione

### Trova l’interfaccia di rete

```bash
ip link show
```

### Modalità osservazione (no blocco)

```bash
sudo ./sentinel eth0
```

### Bloccare uno o più IP

```bash
sudo ./sentinel eth0 -b 8.8.8.8 -b 1.1.1.1
```

---

## 🔄 5. Gestione dinamica della blacklist

È possibile modificare la blacklist **a runtime**, senza riavviare il programma.

### Trova l’ID della mappa

```bash
bpftool map list
```

Esempio:

```text
13: hash  name ip_blacklist
```

---

### ➕ Aggiungere un IP

```bash
bpftool map update id 13 key hex 01 02 03 04 value hex 01 00 00 00
```

👉 Conversione IP → hex:

| IP  | Hex |
| --- | --- |
| 1   | 01  |
| 2   | 02  |
| 255 | ff  |
| 192 | c0  |

---

### 📄 Verificare la blacklist

```bash
bpftool map dump id 13
```

---

### ➖ Rimuovere un IP

```bash
bpftool map delete id 13 key hex 08 08 08 08
```

> ⚡ Le modifiche sono immediate, senza restart.

---

## 🧹 6. Pulizia

```bash
make clean
make
```

---

## 🐛 Problemi comuni

### ❌ `clang: No such file or directory`

→ Installa le dipendenze (Step 1)

---

### ❌ `bpftool: command not found`

→ Installa:

```bash
linux-tools-$(uname -r)
linux-tools-common
```

---

### ❌ `IPPROTO_TCP undeclared`

→ Aggiungi in `xdp_blocker.c`:

```c
#include <linux/in.h>
```

---

### ❌ `XDP_FLAGS_SKB_MODE undeclared`

→ Aggiungi in `loader.c`:

```c
#include <linux/if_link.h>
```

---

### ❌ La mappa `ip_blacklist` non appare

→ Il programma non è in esecuzione
Le mappe esistono solo mentre XDP è attivo

---

## 📚 Riferimenti

* 🌐 https://ebpf.io
* 📦 https://github.com/libbpf/libbpf
* 📝 Serie LinkedIn: cerca *"ebpf-sentinel Davide De Rubeis"*

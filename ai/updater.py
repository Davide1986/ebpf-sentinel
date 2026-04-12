# ai/updater.py
# SPDX-License-Identifier: MIT
# Davide De Rubeis — ebpf-sentinel
#
# Scarica il feed Feodo Tracker (IP botnet aggiornati)
# e aggiorna automaticamente la mappa eBPF ip_blacklist.
#
# Uso:
#   pip install requests
#   sudo python3 updater.py

import subprocess
import socket
import time
import json
import requests

FEED_URL        = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
UPDATE_INTERVAL = 3600  # 1 ora


def get_map_id(map_name: str) -> int:
    try:
        result = subprocess.run(
            ["bpftool", "map", "list", "--json"],
            capture_output=True, text=True
        )
        maps = json.loads(result.stdout)
        for m in maps:
            if m.get("name") == map_name:
                return m["id"]
    except Exception as e:
        print(f"[updater] Errore bpftool: {e}")
    return -1


def ip_to_hex(ip: str) -> list:
    """
    Converte un IP in lista di byte in network byte order.
    Esempio: 8.8.8.8 → [08, 08, 08, 08]
    """
    return list(socket.inet_aton(ip))


def update_map(map_id: int, ip: str) -> bool:
    key_hex = " ".join(f"{b:02x}" for b in ip_to_hex(ip))
    try:
        result = subprocess.run(
            ["bpftool", "map", "update",
             "id", str(map_id),
             "key", "hex"] + key_hex.split() +
            ["value", "hex", "01", "00", "00", "00"],
            capture_output=True
        )
        return result.returncode == 0
    except Exception:
        return False


def fetch_feed() -> list:
    """
    Scarica il feed Feodo Tracker.
    Le righe che iniziano con # sono commenti e vengono ignorate.
    """
    try:
        response = requests.get(FEED_URL, timeout=10)
        response.raise_for_status()
        return [
            line.strip()
            for line in response.text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
    except Exception as e:
        print(f"[updater] Errore download feed: {e}")
        return []


def main():
    print("[updater] ebpf-sentinel — aggiornamento blacklist automatico")
    print(f"[updater] Feed: {FEED_URL}\n")

    while True:
        map_id = get_map_id("ip_blacklist")
        if map_id == -1:
            print("[updater] ATTENZIONE: mappa ip_blacklist non trovata.")
            print("[updater] Verifica che sentinel sia in esecuzione.")
            time.sleep(30)
            continue

        print(f"[updater] Mappa trovata — ID: {map_id}")

        ips = fetch_feed()
        if not ips:
            print("[updater] Feed vuoto o non raggiungibile.")
            time.sleep(UPDATE_INTERVAL)
            continue

        print(f"[updater] {len(ips)} IP da aggiungere alla blacklist...")

        aggiornati = sum(1 for ip in ips if update_map(map_id, ip))
        errori     = len(ips) - aggiornati

        print(f"[updater] Completato — {aggiornati} IP bloccati, "
              f"{errori} errori")
        print(f"[updater] Prossimo aggiornamento tra "
              f"{UPDATE_INTERVAL // 60} minuti.\n")

        time.sleep(UPDATE_INTERVAL)


if __name__ == "__main__":
    main()
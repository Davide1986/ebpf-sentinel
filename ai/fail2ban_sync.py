# ai/fail2ban_sync.py
# SPDX-License-Identifier: MIT
# Davide De Rubeis — ebpf-sentinel
#
# Legge gli IP bannati da Fail2ban e li aggiunge
# alla mappa eBPF ip_blacklist per bloccarli a
# livello driver di rete prima che salgano nello stack.
#
# Reads banned IPs from Fail2ban and adds them to
# the eBPF ip_blacklist map to block them at
# driver level before they reach the network stack.
#
# Uso / Usage:
#   sudo python3 fail2ban_sync.py
#
# Requisiti / Requirements:
#   - fail2ban installato / installed
#   - sentinel in esecuzione / running

import sqlite3
import subprocess
import socket
import ipaddress
import time
import json
from datetime import datetime

# ──────────────────────────────────────────────
# Configurazione / Configuration
# ──────────────────────────────────────────────

# Percorso del database di Fail2ban.
# Path to the Fail2ban database.
FAIL2BAN_DB = "/var/lib/fail2ban/fail2ban.sqlite3"

# Percorso del database di ebpf-sentinel.
# Path to the ebpf-sentinel database.
SENTINEL_DB = "sentinel.db"

# Fonte usata per il logging nel DB sentinel.
# Source name used for logging in sentinel DB.
SOURCE_NAME = "fail2ban"

# Score assegnato agli IP bannati da fail2ban.
# Score assigned to IPs banned by fail2ban.
# Alto perché è una conferma diretta di attacco.
# High because it is a direct attack confirmation.
SCORE = 10

# Intervallo di sincronizzazione in secondi.
# Sync interval in seconds.
SYNC_INTERVAL = 60

# Timeout per i comandi bpftool.
# Timeout for bpftool commands.
BPFTOOL_TIMEOUT = 10


# ──────────────────────────────────────────────
# Utility / Utilities
# ──────────────────────────────────────────────

def is_valid_ipv4(ip: str) -> bool:
    """
    Verifica che la stringa sia un IPv4 valido.
    Verifies that the string is a valid IPv4 address.
    """
    try:
        return isinstance(
            ipaddress.ip_address(ip),
            ipaddress.IPv4Address
        )
    except ValueError:
        return False


def ip_to_hex(ip: str) -> list:
    """
    Converte un IP in lista di byte per bpftool.
    Converts an IP to a byte list for bpftool.
    """
    return list(socket.inet_aton(ip))


# ──────────────────────────────────────────────
# Lettura Fail2ban / Reading Fail2ban
# ──────────────────────────────────────────────

def get_banned_ips() -> list:
    """
    Legge gli IP attualmente bannati da Fail2ban
    dal suo database SQLite.
    Reads currently banned IPs from Fail2ban's
    SQLite database.

    Restituisce solo i ban attivi (timeofban + bantime > now).
    Returns only active bans (timeofban + bantime > now).
    """
    try:
        conn = sqlite3.connect(
            f"file:{FAIL2BAN_DB}?mode=ro",
            uri=True
        )
        now = int(time.time())

        # Seleziona solo i ban ancora attivi.
        # Select only currently active bans.
        # bantime = -1 significa ban permanente.
        # bantime = -1 means permanent ban.
        rows = conn.execute("""
            SELECT DISTINCT ip FROM bans
            WHERE (timeofban + bantime > ?)
               OR bantime = -1
        """, (now,)).fetchall()

        conn.close()
        return [r[0] for r in rows if is_valid_ipv4(r[0])]

    except sqlite3.OperationalError as e:
        print(f"[f2b-sync] Errore lettura Fail2ban DB: {e}")
        print("[f2b-sync] Fail2ban è installato e in esecuzione?")
        return []
    except Exception as e:
        print(f"[f2b-sync] Errore inatteso: {e}")
        return []


# ──────────────────────────────────────────────
# Gestione mappa eBPF / eBPF map management
# ──────────────────────────────────────────────

def get_map_id(map_name: str) -> int:
    """
    Trova l'ID della mappa eBPF tramite bpftool.
    Finds the eBPF map ID using bpftool.
    """
    try:
        result = subprocess.run(
            ["bpftool", "map", "list", "--json"],
            capture_output=True,
            text=True,
            timeout=BPFTOOL_TIMEOUT
        )
        if result.returncode != 0:
            print(f"[f2b-sync] bpftool fallito: {result.stderr.strip()}")
            return -1
        maps = json.loads(result.stdout)
        for m in maps:
            if m.get("name") == map_name:
                return m["id"]
    except subprocess.TimeoutExpired:
        print("[f2b-sync] bpftool timeout")
    except Exception as e:
        print(f"[f2b-sync] Errore bpftool: {e}")
    return -1


def map_add(map_id: int, ip: str) -> bool:
    """
    Aggiunge un IP alla mappa eBPF ip_blacklist.
    Adds an IP to the eBPF ip_blacklist map.
    """
    key_hex = " ".join(f"{b:02x}" for b in ip_to_hex(ip))
    try:
        r = subprocess.run(
            ["bpftool", "map", "update",
             "id", str(map_id),
             "key", "hex"] + key_hex.split() +
            ["value", "hex", "01", "00", "00", "00"],
            capture_output=True,
            text=True,
            timeout=BPFTOOL_TIMEOUT
        )
        if r.returncode != 0:
            print(f"[f2b-sync] map_add fallito per {ip}: "
                  f"{r.stderr.strip()}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"[f2b-sync] map_add timeout per {ip}")
        return False
    except Exception as e:
        print(f"[f2b-sync] Eccezione map_add {ip}: {e}")
        return False


# ──────────────────────────────────────────────
# Logging nel DB sentinel / Logging to sentinel DB
# ──────────────────────────────────────────────

def log_to_sentinel_db(ip: str):
    """
    Registra l'IP nel database di ebpf-sentinel
    con source=fail2ban e score alto.
    Logs the IP in the ebpf-sentinel database
    with source=fail2ban and high score.

    Questo permette di vedere nella dashboard futura
    quali IP sono stati bloccati da fail2ban vs feed.
    This allows seeing in the future dashboard
    which IPs were blocked by fail2ban vs feeds.
    """
    try:
        now = datetime.now(datetime.UTC).isoformat()
        conn = sqlite3.connect(SENTINEL_DB)
        row = conn.execute(
            "SELECT score, sources FROM ip_scores WHERE ip = ?",
            (ip,)
        ).fetchone()

        if row is None:
            conn.execute(
                """INSERT INTO ip_scores
                   (ip, score, sources, source_count,
                    first_seen, last_seen, blocked)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (ip, SCORE, SOURCE_NAME, 1, now, now, 1)
            )
        else:
            score, sources = row
            sources_list = sources.split(",") if sources else []
            if SOURCE_NAME not in sources_list:
                sources_list.append(SOURCE_NAME)
                score += SCORE
            conn.execute(
                """UPDATE ip_scores
                   SET score=?, sources=?, last_seen=?, blocked=1
                   WHERE ip=?""",
                (score, ",".join(sources_list), now, ip)
            )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[f2b-sync] Errore log sentinel DB: {e}")


# ──────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────

def main():
    print("[f2b-sync] ebpf-sentinel — Fail2ban sync")
    print(f"[f2b-sync] Fail2ban DB: {FAIL2BAN_DB}")
    print(f"[f2b-sync] Sentinel DB: {SENTINEL_DB}")
    print(f"[f2b-sync] Score assegnato: {SCORE}")
    print(f"[f2b-sync] Intervallo: {SYNC_INTERVAL}s\n")

    # Tiene traccia degli IP già sincronizzati
    # in questa sessione per evitare chiamate
    # bpftool ripetute inutili.
    # Tracks IPs already synced in this session
    # to avoid unnecessary repeated bpftool calls.
    already_synced = set()

    try:
        while True:
            map_id = get_map_id("ip_blacklist")
            if map_id == -1:
                print("[f2b-sync] Mappa non trovata — "
                      "sentinel in esecuzione?")
                time.sleep(30)
                continue

            banned = get_banned_ips()
            nuovi = [ip for ip in banned
                     if ip not in already_synced]

            if nuovi:
                print(f"[f2b-sync] {len(nuovi)} nuovi IP "
                      f"da sincronizzare")
                sincronizzati = 0
                for ip in nuovi:
                    if map_add(map_id, ip):
                        log_to_sentinel_db(ip)
                        already_synced.add(ip)
                        sincronizzati += 1
                        print(f"[f2b-sync] Bloccato a livello XDP: "
                              f"{ip}")
                print(f"[f2b-sync] Sincronizzati: {sincronizzati}")
            else:
                print(f"[f2b-sync] Nessun nuovo ban — "
                      f"totale attivi: {len(banned)}")

            time.sleep(SYNC_INTERVAL)

    except KeyboardInterrupt:
        print("\n[f2b-sync] Interrotto dall'utente.")


if __name__ == "__main__":
    main()
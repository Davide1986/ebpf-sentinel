# ai/updater.py
# SPDX-License-Identifier: MIT
# Davide De Rubeis — ebpf-sentinel
#
# Aggiornamento automatico della blacklist eBPF
# da feed di threat intelligence esterni.
# Automatic update of the eBPF blacklist
# from external threat intelligence feeds.
#
# Uso / Usage:
#   pip install requests
#   sudo python3 updater.py

import subprocess
import socket
import time
import json
import sqlite3
import requests
from datetime import datetime, timedelta

# ──────────────────────────────────────────────
# Configurazione / Configuration
# ──────────────────────────────────────────────

# Percorso del file che contiene gli URL dei feed.
# Path to the file containing feed URLs.
# Formato / Format:
#   url|peso|nome
#   https://example.com/feed.txt|5|nome_feed
#
# Le righe che iniziano con # sono commenti.
# Lines starting with # are comments.
FEEDS_FILE = "feeds.txt"

# Score minimo per bloccare un IP.
# Un IP viene aggiunto alla blacklist solo se
# la somma dei pesi delle fonti che lo segnalano
# raggiunge questa soglia.
# Minimum score to block an IP.
# An IP is added to the blacklist only if
# the sum of weights from sources reporting it
# reaches this threshold.
MIN_SCORE = 3

# Ore dopo cui un IP viene rimosso dalla blacklist
# se non compare più in nessun feed.
# Hours after which an IP is removed from the blacklist
# if it no longer appears in any feed.
TTL_HOURS = 48

# Intervallo di aggiornamento in secondi.
# Update interval in seconds.
UPDATE_INTERVAL = 3600  # 1 ora / 1 hour

# Percorso del database SQLite.
# Path to the SQLite database.
DB_PATH = "sentinel.db"


# ──────────────────────────────────────────────
# Lettura feed da file / Reading feeds from file
# ──────────────────────────────────────────────

def load_feeds(filepath: str) -> list:
    """
    Legge la lista dei feed dal file di configurazione.
    Reading the list of feeds from the configuration file.

    Formato atteso / Expected format:
        url|peso|nome
        https://example.com/feed.txt|5|feodo

    Righe vuote e commenti (#) vengono ignorati.
    Empty lines and comments (#) are ignored.

    Quando in futuro si userà un database, questa
    funzione verrà sostituita da una query SQL
    mantenendo identica l'interfaccia verso il resto
    del codice.
    When a database is used in the future, this
    function will be replaced by a SQL query
    keeping the same interface toward the rest
    of the code.
    """
    feeds = []
    try:
        with open(filepath, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()

                # Salta righe vuote e commenti
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                parts = line.split("|")
                if len(parts) != 3:
                    print(f"[updater] Riga {lineno} ignorata "
                          f"(formato errato): {line}")
                    continue

                url, weight_str, name = parts[0].strip(), \
                                        parts[1].strip(), \
                                        parts[2].strip()
                try:
                    weight = int(weight_str)
                except ValueError:
                    print(f"[updater] Riga {lineno}: peso non valido "
                          f"'{weight_str}', uso 1")
                    weight = 1

                feeds.append((name, url, weight))

    except FileNotFoundError:
        print(f"[updater] File {filepath} non trovato. "
              f"File {filepath} not found.")
    except Exception as e:
        print(f"[updater] Errore lettura {filepath}: {e}")

    return feeds


# ──────────────────────────────────────────────
# Database SQLite
# ──────────────────────────────────────────────

def init_db() -> sqlite3.Connection:
    """
    Inizializza il database SQLite.
    Initializes the SQLite database.

    La tabella ip_scores tiene traccia di ogni IP,
    il suo score totale, le fonti che lo segnalano
    e i timestamp di prima e ultima rilevazione.
    The ip_scores table tracks each IP, its total
    score, the sources reporting it, and the
    timestamps of first and last detection.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_scores (
            ip          TEXT PRIMARY KEY,
            score       INTEGER DEFAULT 0,
            sources     TEXT DEFAULT '',
            first_seen  TEXT,
            last_seen   TEXT,
            blocked     INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    return conn


def update_score(conn: sqlite3.Connection,
                 ip: str, source: str, weight: int):
    """
    Aggiorna lo score di un IP nel database.
    Updates the score of an IP in the database.

    Se la fonte è già presente per questo IP
    non aggiunge il peso due volte — evita
    che lo stesso feed conti più volte per ciclo.
    If the source is already present for this IP,
    the weight is not added twice — prevents
    the same feed from counting multiple times
    per cycle.
    """
    now = datetime.utcnow().isoformat()
    row = conn.execute(
        "SELECT score, sources FROM ip_scores WHERE ip = ?",
        (ip,)
    ).fetchone()

    if row is None:
        # Primo avvistamento / First detection
        conn.execute(
            "INSERT INTO ip_scores VALUES (?,?,?,?,?,?)",
            (ip, weight, source, now, now, 0)
        )
    else:
        score, sources = row
        sources_list = sources.split(",") if sources else []
        if source not in sources_list:
            sources_list.append(source)
            score += weight
        conn.execute(
            """UPDATE ip_scores
               SET score=?, sources=?, last_seen=?
               WHERE ip=?""",
            (score, ",".join(sources_list), now, ip)
        )


def get_ips_to_block(conn: sqlite3.Connection) -> list:
    """
    Restituisce gli IP con score sufficiente
    non ancora bloccati.
    Returns IPs with sufficient score
    not yet blocked.
    """
    rows = conn.execute(
        """SELECT ip FROM ip_scores
           WHERE score >= ? AND blocked = 0""",
        (MIN_SCORE,)
    ).fetchall()
    return [r[0] for r in rows]


def get_ips_to_expire(conn: sqlite3.Connection) -> list:
    """
    Restituisce gli IP bloccati non aggiornati
    da più di TTL_HOURS — candidati alla rimozione.
    Returns blocked IPs not updated for more than
    TTL_HOURS — candidates for removal.
    """
    cutoff = (
        datetime.utcnow() - timedelta(hours=TTL_HOURS)
    ).isoformat()
    rows = conn.execute(
        """SELECT ip FROM ip_scores
           WHERE last_seen < ? AND blocked = 1""",
        (cutoff,)
    ).fetchall()
    return [r[0] for r in rows]


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
            capture_output=True, text=True
        )
        maps = json.loads(result.stdout)
        for m in maps:
            if m.get("name") == map_name:
                return m["id"]
    except Exception as e:
        print(f"[updater] Errore bpftool / bpftool error: {e}")
    return -1


def ip_to_hex(ip: str) -> list:
    """
    Converte un IP in lista di byte per bpftool.
    Converts an IP to a byte list for bpftool.
    Esempio / Example: 8.8.8.8 → [08, 08, 08, 08]
    """
    return list(socket.inet_aton(ip))


def map_add(map_id: int, ip: str) -> bool:
    """
    Aggiunge un IP alla mappa eBPF.
    Adds an IP to the eBPF map.
    """
    key_hex = " ".join(f"{b:02x}" for b in ip_to_hex(ip))
    try:
        r = subprocess.run(
            ["bpftool", "map", "update",
             "id", str(map_id),
             "key", "hex"] + key_hex.split() +
            ["value", "hex", "01", "00", "00", "00"],
            capture_output=True
        )
        return r.returncode == 0
    except Exception:
        return False


def map_remove(map_id: int, ip: str) -> bool:
    """
    Rimuove un IP dalla mappa eBPF.
    Removes an IP from the eBPF map.
    """
    key_hex = " ".join(f"{b:02x}" for b in ip_to_hex(ip))
    try:
        r = subprocess.run(
            ["bpftool", "map", "delete",
             "id", str(map_id),
             "key", "hex"] + key_hex.split(),
            capture_output=True
        )
        return r.returncode == 0
    except Exception:
        return False


# ──────────────────────────────────────────────
# Download feed / Feed download
# ──────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    """
    Verifica che la stringa sia un IPv4 valido.
    Verifies that the string is a valid IPv4.
    """
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


def fetch_feed(url: str) -> list:
    """
    Scarica un feed e restituisce IP validi.
    Downloads a feed and returns valid IPs.

    Gestisce automaticamente / Handles automatically:
    - Commenti (#) / Comments (#)
    - Notazione CIDR (1.2.3.0/24) / CIDR notation
    - Colonne extra separate da spazi o ; / Extra columns
    """
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        ips = []
        for line in response.text.splitlines():
            candidate = (
                line.strip().split()[0] if line.strip() else ""
            )
            if not candidate or candidate.startswith("#"):
                continue
            # Rimuove notazione CIDR / Remove CIDR notation
            ip = candidate.split("/")[0]
            if is_valid_ip(ip):
                ips.append(ip)
        return ips
    except Exception as e:
        print(f"[updater] Errore download {url}: {e}")
        return []


# ──────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────

def main():
    print("[updater] ebpf-sentinel — threat intelligence engine")
    print(f"[updater] Database: {DB_PATH}")
    print(f"[updater] Score minimo / Minimum score: {MIN_SCORE}")
    print(f"[updater] TTL IP: {TTL_HOURS} ore / hours\n")

    # Inizializza database / Initialize database
    conn = init_db()

    while True:
        # Verifica che sentinel sia in esecuzione
        # Check that sentinel is running
        map_id = get_map_id("ip_blacklist")
        if map_id == -1:
            print("[updater] ATTENZIONE / WARNING: "
                  "mappa ip_blacklist non trovata.")
            print("[updater] Verifica che sentinel sia in esecuzione.")
            print("[updater] Make sure sentinel is running.")
            time.sleep(30)
            continue

        print(f"[updater] Mappa trovata — ID: {map_id}")
        print(f"[updater] Ciclo: "
              f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")

        # Carica i feed dal file di configurazione
        # Load feeds from the configuration file
        feeds = load_feeds(FEEDS_FILE)
        if not feeds:
            print(f"[updater] Nessun feed in {FEEDS_FILE}. "
                  f"No feeds in {FEEDS_FILE}.")
            time.sleep(UPDATE_INTERVAL)
            continue

        print(f"[updater] Feed caricati / Loaded feeds: {len(feeds)}")

        # Reset score per il ciclo corrente
        # Reset score for the current cycle
        conn.execute("UPDATE ip_scores SET score = 0, sources = ''")
        conn.commit()

        # Scarica tutti i feed e calcola gli score
        # Download all feeds and calculate scores
        for name, url, weight in feeds:
            print(f"[updater] Feed: {name} (peso/weight: {weight})")
            ips = fetch_feed(url)
            print(f"[updater] → {len(ips)} IP trovati / found")
            for ip in ips:
                update_score(conn, ip, name, weight)
            conn.commit()

        # Blocca i nuovi IP con score sufficiente
        # Block new IPs with sufficient score
        da_bloccare = get_ips_to_block(conn)
        print(f"\n[updater] Da bloccare / To block "
              f"(score >= {MIN_SCORE}): {len(da_bloccare)}")

        bloccati = 0
        for ip in da_bloccare:
            if map_add(map_id, ip):
                conn.execute(
                    "UPDATE ip_scores SET blocked=1 WHERE ip=?",
                    (ip,)
                )
                bloccati += 1
        conn.commit()
        print(f"[updater] Bloccati / Blocked: {bloccati}")

        # Rimuove gli IP scaduti / Remove expired IPs
        da_rimuovere = get_ips_to_expire(conn)
        print(f"[updater] Scaduti / Expired: {len(da_rimuovere)}")

        rimossi = 0
        for ip in da_rimuovere:
            if map_remove(map_id, ip):
                conn.execute(
                    "DELETE FROM ip_scores WHERE ip=?", (ip,)
                )
                rimossi += 1
        conn.commit()
        print(f"[updater] Rimossi / Removed: {rimossi}")

        print(f"\n[updater] Completato. Prossimo aggiornamento / "
              f"Next update: {UPDATE_INTERVAL // 60} min.\n")

        time.sleep(UPDATE_INTERVAL)


if __name__ == "__main__":
    main()